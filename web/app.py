"""Web API for computer-audit.

Endpoints:
  POST /scan/iam       - IAM blast radius
  POST /scan/forensics - forensics triage
  POST /scan/api       - API scanner
  GET  /graph/iam      - IAM graph in DOT format
  POST /ai/explain     - AI explanation of a finding

Run:  python -m cli.main web
"""

from __future__ import annotations

from typing import Any

try:  # FastAPI is optional; the CLI works without it
    from fastapi import FastAPI
    from pydantic import BaseModel
except Exception:  # pragma: no cover - fastapi not installed
    FastAPI = None  # type: ignore
    BaseModel = object  # type: ignore

from core.ai_enhancer import build_enhancer
from core.audit_cmd import _asdict
from core.api_scanner import APIScanner
from core.bloat_auditor import BloatAuditor
from core.forensics import Forensics
from core.iam_auditor import IAMAuditor, load_sample_dump
from core.threat_scanner import ThreatScanner


class IAMRequest(BaseModel):  # type: ignore[misc]
    input: str | None = None
    compromised: str = "user:alice"
    ai: bool = False


class ForensicsRequest(BaseModel):  # type: ignore[misc]
    dump: str | None = None
    log: str | None = None
    processes: list[dict[str, str]] | None = None
    ai: bool = False


class APIRequest(BaseModel):  # type: ignore[misc]
    target: str
    timeout: int = 8
    ai: bool = False


class ExplainRequest(BaseModel):  # type: ignore[misc]
    finding: dict[str, Any]
    kind: str = "iam"
    ai: bool = False


# ---- Security & bloat audit request models (module level for FastAPI) ----
class AuditBloatRequest(BaseModel):  # type: ignore[misc]
    output: str | None = None
    ai: bool = False


class AuditThreatRequest(BaseModel):  # type: ignore[misc]
    output: str | None = None
    paths: list[str] | None = None
    ai: bool = False


class AuditFullRequest(BaseModel):  # type: ignore[misc]
    output: str | None = None


class AuditRemovalRequest(BaseModel):  # type: ignore[misc]
    bloat_report: str | None = None
    apply: bool = False


def build_app() -> Any:
    if FastAPI is None:  # pragma: no cover
        raise RuntimeError("fastapi not installed. pip install -r requirements.txt")

    app = FastAPI(title="computer-audit", version="1.0.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/scan/iam")
    def scan_iam(req: IAMRequest) -> dict[str, Any]:
        auditor = IAMAuditor()
        if req.input:
            auditor.load_dump(req.input)
        else:
            sample = load_sample_dump()
            auditor.identities = {i["id"]: i for i in sample["identities"]}
            auditor.roles = {r["id"]: r for r in sample["roles"]}
            auditor.policies = {p["id"]: p for p in sample["policies"]}
            auditor.resources = {r["id"]: r for r in sample["resources"]}
            auditor._build_edges(sample["resource_access"])
        radius = auditor.compute_blast_radius(req.compromised)
        result = auditor.to_json(radius)
        if req.ai:
            enhancer = build_enhancer(force_llm=True)
            result["ai_summary"] = enhancer.summarize(result["findings"], "iam")
        return result

    @app.post("/scan/forensics")
    def scan_forensics(req: ForensicsRequest) -> dict[str, Any]:
        fr = Forensics()
        report = fr.triage(dump_path=req.dump, log_path=req.log, proclist=req.processes)
        return {
            "summary": report.summary,
            "indicators": report.indicators,
            "suspicious_processes": report.suspicious_processes,
            "log_hits": report.log_hits,
        }

    @app.post("/scan/api")
    def scan_api(req: APIRequest) -> dict[str, Any]:
        scanner = APIScanner(timeout=req.timeout)
        return scanner.scan(req.target)

    @app.get("/graph/iam")
    def graph_iam(compromised: str = "user:alice") -> dict[str, str]:
        auditor = IAMAuditor()
        sample = load_sample_dump()
        auditor.identities = {i["id"]: i for i in sample["identities"]}
        auditor.roles = {r["id"]: r for r in sample["roles"]}
        auditor.policies = {p["id"]: p for p in sample["policies"]}
        auditor.resources = {r["id"]: r for r in sample["resources"]}
        auditor._build_edges(sample["resource_access"])
        radius = auditor.compute_blast_radius(compromised)
        return {"dot": auditor.to_dot(radius)}

    @app.post("/ai/explain")
    def ai_explain(req: ExplainRequest) -> dict[str, str]:
        enhancer = build_enhancer(force_llm=req.ai)
        return {"explain": enhancer.explain(req.finding, req.kind)}

    @app.post("/audit/bloat")
    def web_audit_bloat(req: AuditBloatRequest) -> dict[str, Any]:
        report = BloatAuditor().audit()
        payload = _asdict(report)
        if req.ai:
            from core.ai_enhancer import build_enhancer as _be
            payload["ai_summary"] = _be(force_llm=True).summarize(
                [{"title": "bloat-audit", "detail": report.summary, "severity": "medium"}], "bloat"
            )
        if req.output:
            import json
            from pathlib import Path
            out = Path(req.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    @app.post("/audit/threat")
    def web_audit_threat(req: AuditThreatRequest) -> dict[str, Any]:
        report = ThreatScanner().scan(extra_paths=req.paths)
        payload = _asdict(report)
        if req.ai:
            from core.ai_enhancer import build_enhancer as _be
            payload["ai_summary"] = _be(force_llm=True).summarize(
                [{"title": "threat-scan", "detail": report.summary, "severity": "medium"}], "threat"
            )
        if req.output:
            import json
            from pathlib import Path
            out = Path(req.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    @app.post("/audit/full")
    def web_audit_full(req: AuditFullRequest) -> dict[str, Any]:
        payload = {
            "bloat": _asdict(BloatAuditor().audit()),
            "threat": _asdict(ThreatScanner().scan()),
        }
        if req.output:
            import json
            from pathlib import Path
            out = Path(req.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    @app.post("/audit/removal")
    def web_audit_removal(req: AuditRemovalRequest) -> dict[str, Any]:
        import json
        from pathlib import Path
        from core.removal_engine import RemovalEngine
        bloat_report = None
        if req.bloat_report and Path(req.bloat_report).exists():
            bloat_report = json.loads(Path(req.bloat_report).read_text(encoding="utf-8"))
        else:
            bloat_report = _asdict(BloatAuditor().audit())
        engine = RemovalEngine(dry_run=not req.apply)
        planned = engine.plan_from_bloat(bloat_report)
        if req.apply:
            result = engine.apply(planned, confirm=True)
            return {
                "planned": result.planned,
                "applied": result.applied,
                "skipped": result.skipped,
                "failed": result.failed,
                "log_path": result.log_path,
                "sha256": engine.hash_log(result.log_path),
                "dry_run": False,
            }
        return {
            "planned": len(planned),
            "preview": engine.preview(planned),
            "dry_run": True,
            "message": "Dry run only. Set apply=true to execute.",
        }

    return app


app = build_app() if FastAPI is not None else None
