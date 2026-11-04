"""Modern IAM Visualization & Auditing.

Builds a directed permission graph from normalized IAM dumps (AWS/Azure/GCP style),
computes blast radius from a compromised identity, and surfaces privilege-escalation
paths. Output is plain JSON + Graphviz DOT so any OS can render it (graphviz,
web viz, or plain text).

Input schema (JSON):
{
  "identities": [{"id": "user:alice", "type": "user", "groups": ["dev"]}],
  "roles": [{"id": "role:Admin", "assumable_by": ["group:dev"], "policies": ["pol:Admin"]}],
  "policies": [{"id": "pol:Admin", "actions": ["*"], "resources": ["*"]}],
  "resources": [{"id": "res:s3-bucket", "type": "s3", "sensitive": true}],
  "resource_access": [{"role": "role:Admin", "resource": "res:s3-bucket", "action": "*"}]
}
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Edge:
    src: str
    dst: str
    label: str


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class BlastRadius:
    compromised_identity: str
    reachable_identities: list[str]
    reachable_roles: list[str]
    reachable_resources: list[str]
    sensitive_resources: list[str]
    escalation_paths: list[list[str]]


class IAMAuditor:
    """IAM permission graph auditor."""

    def __init__(self) -> None:
        self.identities: dict[str, dict[str, Any]] = {}
        self.roles: dict[str, dict[str, Any]] = {}
        self.policies: dict[str, dict[str, Any]] = {}
        self.resources: dict[str, dict[str, Any]] = {}
        self.edges: list[Edge] = []

    # ------------------------------------------------------------------ load
    def load_dump(self, path: str) -> None:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for ident in data.get("identities", []):
            self.identities[ident["id"]] = ident
        for role in data.get("roles", []):
            self.roles[role["id"]] = role
        for pol in data.get("policies", []):
            self.policies[pol["id"]] = pol
        for res in data.get("resources", []):
            self.resources[res["id"]] = res
        self._build_edges(data.get("resource_access", []))

    def _build_edges(self, access: list[dict[str, Any]]) -> None:
        self.edges = []
        for role_id, role in self.roles.items():
            for group in role.get("assumable_by", []):
                for member in self._members_of(group):
                    self.edges.append(Edge(member, role_id, "assume"))
            for pol_id in role.get("policies", []):
                self.edges.append(Edge(role_id, pol_id, "has-policy"))
            for acc in access:
                if acc["role"] == role_id:
                    self.edges.append(Edge(role_id, acc["resource"], f"access:{acc.get('action', '*')}"))
        for pol_id, pol in self.policies.items():
            for res_id in pol.get("resources", ["*"]):
                self.edges.append(Edge(pol_id, res_id, f"policy:{','.join(pol.get('actions', ['*']))}"))

    def _members_of(self, group: str) -> list[str]:
        return [iid for iid, ident in self.identities.items() if group in ident.get("groups", [])]

    # ------------------------------------------------------------ blast radius
    def compute_blast_radius(self, compromised_identity: str) -> BlastRadius:
        if compromised_identity not in self.identities:
            raise ValueError(f"Unknown identity: {compromised_identity}")

        adj: dict[str, list[tuple[str, str]]] = {}
        for e in self.edges:
            adj.setdefault(e.src, []).append((e.dst, e.label))

        visited: set[str] = {compromised_identity}
        queue: deque[tuple[str, list[str]]] = deque([(compromised_identity, [compromised_identity])])
        escalation_paths: list[list[str]] = []

        while queue:
            node, path = queue.popleft()
            for dst, _label in adj.get(node, []):
                if dst in visited:
                    continue
                visited.add(dst)
                new_path = path + [dst]
                # privilege escalation = reaching a role not originally held
                if dst in self.roles and dst not in self._roles_of(compromised_identity):
                    escalation_paths.append(new_path)
                queue.append((dst, new_path))

        reachable_identities = sorted(n for n in visited if n in self.identities)
        reachable_roles = sorted(n for n in visited if n in self.roles)
        reachable_resources = sorted(n for n in visited if n in self.resources)
        sensitive = [r for r in reachable_resources if self.resources[r].get("sensitive")]

        return BlastRadius(
            compromised_identity=compromised_identity,
            reachable_identities=reachable_identities,
            reachable_roles=reachable_roles,
            reachable_resources=reachable_resources,
            sensitive_resources=sensitive,
            escalation_paths=escalation_paths,
        )

    def _roles_of(self, identity: str) -> set[str]:
        groups = self.identities[identity].get("groups", [])
        return {rid for rid, role in self.roles.items() if any(g in role.get("assumable_by", []) for g in groups)}

    # --------------------------------------------------------------- findings
    def findings(self, radius: BlastRadius) -> list[Finding]:
        out: list[Finding] = []
        sev = "critical" if radius.sensitive_resources else "high"
        out.append(
            Finding(
                id="iam-blast-radius",
                title=f"Blast radius from {radius.compromised_identity}",
                severity=sev,
                detail=(
                    f"Compromising {radius.compromised_identity} can reach "
                    f"{len(radius.reachable_roles)} role(s) and {len(radius.reachable_resources)} "
                    f"resource(s), including {len(radius.sensitive_resources)} sensitive resource(s)."
                ),
                evidence=asdict(radius),
            )
        )
        for path in radius.escalation_paths[:5]:
            out.append(
                Finding(
                    id="iam-priv-esc",
                    title="Privilege escalation path",
                    severity="high",
                    detail=" -> ".join(path),
                    evidence={"path": path},
                )
            )
        for role_id, role in self.roles.items():
            for pol_id in role.get("policies", []):
                pol = self.policies.get(pol_id, {})
                if "*" in pol.get("actions", []):
                    out.append(
                        Finding(
                            id=f"iam-wildcard-{role_id}",
                            title=f"Wildcard action on {role_id}",
                            severity="medium",
                            detail=f"Role {role_id} has policy {pol_id} with action '*'.",
                            evidence={"role": role_id, "policy": pol_id},
                        )
                    )
        return out

    # --------------------------------------------------------------- export
    def to_dot(self, radius: BlastRadius | None = None) -> str:
        lines = ["digraph IAM {", '  rankdir=LR;', '  node [shape=box];']
        for e in self.edges:
            lines.append(f'  "{e.src}" -> "{e.dst}" [label="{e.label}"];')
        if radius:
            for r in radius.sensitive_resources:
                lines.append(f'  "{r}" [shape=doubleoctagon, color=red];')
            lines.append(f'  "{radius.compromised_identity}" [color=red, style=filled, fillcolor=pink];')
        lines.append("}")
        return "\n".join(lines)

    def to_json(self, radius: BlastRadius) -> dict[str, Any]:
        return {
            "compromised_identity": radius.compromised_identity,
            "reachable_identities": radius.reachable_identities,
            "reachable_roles": radius.reachable_roles,
            "reachable_resources": radius.reachable_resources,
            "sensitive_resources": radius.sensitive_resources,
            "escalation_paths": radius.escalation_paths,
            "edges": [asdict(e) for e in self.edges],
            "findings": [asdict(f) for f in self.findings(radius)],
        }


def load_sample_dump() -> dict[str, Any]:
    return {
        "identities": [
            {"id": "user:alice", "type": "user", "groups": ["group:dev"]},
            {"id": "user:bob", "type": "user", "groups": ["group:ops"]},
            {"id": "svc:ci-key", "type": "service-account", "groups": ["group:ci"]},
        ],
        "roles": [
            {"id": "role:Developer", "assumable_by": ["group:dev"], "policies": ["pol:DevWrite"]},
            {"id": "role:Admin", "assumable_by": ["group:ops"], "policies": ["pol:Admin"]},
            {"id": "role:CIDeploy", "assumable_by": ["group:ci"], "policies": ["pol:CIWrite"]},
        ],
        "policies": [
            {"id": "pol:DevWrite", "actions": ["s3:PutObject"], "resources": ["res:app-bucket"]},
            {"id": "pol:Admin", "actions": ["*"], "resources": ["*"]},
            {"id": "pol:CIWrite", "actions": ["sts:AssumeRole"], "resources": ["role:Admin"]},
        ],
        "resources": [
            {"id": "res:app-bucket", "type": "s3", "sensitive": False},
            {"id": "res:prod-db", "type": "rds", "sensitive": True},
            {"id": "res:secrets-manager", "type": "secrets", "sensitive": True},
        ],
        "resource_access": [
            {"role": "role:Developer", "resource": "res:app-bucket", "action": "s3:PutObject"},
            {"role": "role:Admin", "resource": "res:prod-db", "action": "*"},
            {"role": "role:Admin", "resource": "res:secrets-manager", "action": "*"},
        ],
    }
