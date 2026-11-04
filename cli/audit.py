"""Unified audit CLI: bloat + threat + removal.

Usage:
  python -m cli.main audit bloat        # detect bloat / AI bloat
  python -m cli.main audit threat       # threat triage
  python -m cli.main audit removal --preview  # plan removal (dry-run)
  python -m cli.main audit removal --apply    # apply (confirmation required)
  python -m cli.main audit full         # bloat + threat together
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.bloat_auditor import BloatAuditor  # noqa: E402
from core.threat_scanner import ThreatScanner  # noqa: E402
from core.removal_engine import RemovalEngine  # noqa: E402
from core.ai_enhancer import build_enhancer  # noqa: E402


def _write(path: str | None, payload: object) -> None:
    text = json.dumps(payload, indent=2, default=str)
    if path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"Wrote {path}")
    else:
        print(text)


def cmd_audit_bloat(args: argparse.Namespace) -> int:
    report = BloatAuditor().audit()
    payload = dataclasses_asdict(report)
    if args.ai:
        enhancer = build_enhancer(force_llm=True)
        payload["ai_summary"] = enhancer.summarize(
            [{"title": "bloat-audit", "detail": report.summary, "severity": "medium"}], "bloat"
        )
    _write(args.output, payload)
    print(report.summary)
    return 0


def cmd_audit_threat(args: argparse.Namespace) -> int:
    scanner = ThreatScanner()
    report = scanner.scan(extra_paths=args.paths)
    payload = dataclasses_asdict(report)
    if args.ai:
        enhancer = build_enhancer(force_llm=True)
        payload["ai_summary"] = enhancer.summarize(
            [{"title": "threat-scan", "detail": report.summary, "severity": "medium"}], "threat"
        )
    _write(args.output, payload)
    print(report.summary)
    return 0


def cmd_audit_removal(args: argparse.Namespace) -> int:
    # Load previous reports if present; otherwise run a quick bloat audit to plan.
    bloat_report = None
    if args.bloat_report and Path(args.bloat_report).exists():
        bloat_report = json.loads(Path(args.bloat_report).read_text(encoding="utf-8"))
    else:
        bloat_report = BloatAuditor().audit().__dict__ if hasattr(BloatAuditor().audit(), "__dict__") else BloatAuditor().audit()

    engine = RemovalEngine(dry_run=not args.apply)
    planned = engine.plan_from_bloat(bloat_report)

    print(engine.preview(planned))
    if args.apply:
        result = engine.apply(planned, confirm=True)
        print(f"Applied: {result.applied}, Skipped: {result.skipped}, Failed: {result.failed}")
        print(f"Log: {result.log_path}")
        print(f"SHA256: {engine.hash_log(result.log_path)}")
    else:
        print("Dry run only. Re-run with --apply to execute (requires confirmation).")
    return 0


def dataclasses_asdict(obj):
    import dataclasses
    return dataclasses.asdict(obj)


def build_audit_parser(sub) -> None:
    p = sub.add_parser("audit", help="Security & bloat audit")
    a_sub = p.add_subparsers(dest="audit_cmd", required=True)

    pb = a_sub.add_parser("bloat", help="Audit bloat / AI bloat")
    pb.add_argument("--output", help="Write JSON report")
    pb.add_argument("--ai", action="store_true", help="AI summary (needs AI_API_BASE/AI_API_KEY)")
    pb.set_defaults(func=cmd_audit_bloat)

    pt = a_sub.add_parser("threat", help="Threat / trojan triage scan")
    pt.add_argument("--output", help="Write JSON report")
    pt.add_argument("--paths", nargs="*", help="Extra files to scan for indicators")
    pt.add_argument("--ai", action="store_true", help="AI summary")
    pt.set_defaults(func=cmd_audit_threat)

    pr = a_sub.add_parser("removal", help="Plan & apply bloat removal")
    pr.add_argument("--bloat-report", help="Existing bloat JSON report to plan from")
    pr.add_argument("--apply", action="store_true", help="Execute removal (confirmation required)")
    pr.set_defaults(func=cmd_audit_removal)

    pf = a_sub.add_parser("full", help="Full audit: bloat + threat")
    pf.add_argument("--output", help="Write combined JSON report")
    pf.set_defaults(func=cmd_audit_full)


def cmd_audit_full(args: argparse.Namespace) -> int:
    bloat = BloatAuditor().audit()
    threat = ThreatScanner().scan()
    payload = {
        "bloat": dataclasses_asdict(bloat),
        "threat": dataclasses_asdict(threat),
    }
    _write(args.output, payload)
    print(bloat.summary)
    print(threat.summary)
    return 0


def attach_audit_subparsers(build_parser) -> None:
    """Called from cli/main.py to register audit subcommands."""
    pass  # kept for compatibility; audit registered inline below
