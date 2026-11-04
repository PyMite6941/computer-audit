"""Audit command registration + runner for security & bloat audits."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from core.ai_enhancer import build_enhancer
from core.bloat_auditor import BloatAuditor
from core.removal_engine import RemovalEngine
from core.threat_scanner import ThreatScanner


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
    payload = _asdict(report)
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
    payload = _asdict(report)
    if args.ai:
        enhancer = build_enhancer(force_llm=True)
        payload["ai_summary"] = enhancer.summarize(
            [{"title": "threat-scan", "detail": report.summary, "severity": "medium"}], "threat"
        )
    _write(args.output, payload)
    print(report.summary)
    return 0


def cmd_audit_removal(args: argparse.Namespace) -> int:
    bloat_report = None
    if args.bloat_report and Path(args.bloat_report).exists():
        bloat_report = json.loads(Path(args.bloat_report).read_text(encoding="utf-8"))
    else:
        bloat_report = _asdict(BloatAuditor().audit())

    engine = RemovalEngine(dry_run=not args.apply)
    planned = engine.plan_from_bloat(bloat_report)
    print(engine.preview(planned))
    if args.apply:
        result = engine.apply(planned, confirm=True)
        print(f"Applied: {result.applied}, Skipped: {result.skipped}, Failed: {result.failed}")
        print(f"Log: {result.log_path}")
        print(f"SHA256: {engine.hash_log(result.log_path)}")
    else:
        print("Dry run only. Re-run with --apply to execute.")
    return 0


def cmd_audit_full(args: argparse.Namespace) -> int:
    payload = {
        "bloat": _asdict(BloatAuditor().audit()),
        "threat": _asdict(ThreatScanner().scan()),
    }
    _write(args.output, payload)
    print(payload["bloat"]["summary"])
    print(payload["threat"]["summary"])
    return 0


def _asdict(obj: Any) -> dict[str, Any]:
    import dataclasses

    return dataclasses.asdict(obj)


def run_audit(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="computer-audit audit", description="Security & bloat audit")
    sub = parser.add_subparsers(dest="audit_cmd", required=True)

    pb = sub.add_parser("bloat", help="Audit bloat / AI bloat")
    pb.add_argument("--output", help="Write JSON report")
    pb.add_argument("--ai", action="store_true", help="AI summary (needs AI_API_BASE/AI_API_KEY)")
    pb.set_defaults(func=cmd_audit_bloat)

    pt = sub.add_parser("threat", help="Threat / trojan triage scan")
    pt.add_argument("--output", help="Write JSON report")
    pt.add_argument("--paths", nargs="*", help="Extra files to scan for indicators")
    pt.add_argument("--ai", action="store_true", help="AI summary")
    pt.set_defaults(func=cmd_audit_threat)

    pr = sub.add_parser("removal", help="Plan & apply bloat removal")
    pr.add_argument("--bloat-report", help="Existing bloat JSON report")
    pr.add_argument("--output", help="Write removal plan/log JSON")
    pr.add_argument("--apply", action="store_true", help="Execute removal")
    pr.set_defaults(func=cmd_audit_removal)

    pf = sub.add_parser("full", help="Full audit: bloat + threat")
    pf.add_argument("--output", help="Write combined JSON report")
    pf.set_defaults(func=cmd_audit_full)

    args = parser.parse_args(argv)
    return args.func(args)
