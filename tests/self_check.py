# Threat hunting / forensics quick checks — run from repo root:
#   python tests/self_check.py   (venv activated)
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.iam_auditor import IAMAuditor, load_sample_dump
from core.forensics import Forensics, sample_proc_list
from core.api_scanner import APIScanner

# 1. IAM blast radius
a = IAMAuditor()
s = load_sample_dump()
a.identities = {i["id"]: i for i in s["identities"]}
a.roles = {r["id"]: r for r in s["roles"]}
a.policies = {p["id"]: p for p in s["policies"]}
a.resources = {r["id"]: r for r in s["resources"]}
a._build_edges(s["resource_access"])
r = a.compute_blast_radius("svc:ci-key")
assert "role:Admin" in r.reachable_roles, r.reachable_roles
assert "res:prod-db" in r.sensitive_resources, r.sensitive_resources
assert any("role:Admin" in p for p in r.escalation_paths), r.escalation_paths
print("IAM OK:", len(r.reachable_roles), "roles,", len(r.sensitive_resources), "sensitive")

# 2. Forensics
f = Forensics()
inds = f.extract_indicators("connect to 10.0.0.99 and AKIAIOSFODNN7EXAMPLE", "test")
assert any(i.type == "ip" for i in inds)
assert any(i.type == "aws_key" for i in inds)
procs = f.suspicious_processes(sample_proc_list())
assert any(p["name"] == "mimikatz.exe" for p in procs)
print("Forensics OK:", len(inds), "indicators,", len(procs), "suspicious procs")

# 3. API scanner (offline discovery only, no network target)
sc = APIScanner(timeout=2)
eps = sc.discover_endpoints("http://127.0.0.1:1")
print("API scanner OK (offline), endpoints:", eps)

print("ALL SELF-CHECKS PASSED")
