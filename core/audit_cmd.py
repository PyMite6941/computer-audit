"""Audit command registration + runner for security & bloat audits.

Features:
- Parallel backend scanning: bloat + threat run concurrently via ThreadPoolExecutor.
- Port scanning included in threat scan.
- AI thinker (separate from enhancer) provides pre-audit reasoning.
- Fix proposal before approval: removal shows a planned-action list and requires
  --apply + confirmation before any system change.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from core.ai_enhancer import build_enhancer
from core.ai_thinker import build_thinker
from core.bloat_auditor import BloatAuditor
from core.errors import AuditError, handle_error
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


def _asdict(obj: Any) -> dict[str, Any]:
    import dataclasses

    return dataclasses.asdict(obj)


# ---------------------------------------------------------------- parallel runner
def _run_bloat(ai: bool) -> dict[str, Any]:
    report = BloatAuditor().audit()
    payload = _asdict(report)
    if ai:
        enhancer = build_enhancer(force_llm=True)
        payload["ai_summary"] = enhancer.summarize(
            [{"title": "bloat-audit", "detail": report.summary, "severity": "medium"}], "bloat"
        )
    return payload


def _run_threat(ai: bool, paths: list[str] | None) -> dict[str, Any]:
    scanner = ThreatScanner()
    report = scanner.scan(extra_paths=paths)
    payload = _asdict(report)
    if ai:
        enhancer = build_enhancer(force_llm=True)
        payload["ai_summary"] = enhancer.summarize(
            [{"title": "threat-scan", "detail": report.summary, "severity": "medium"}], "threat"
        )
    return payload


def _run_thinker(bloat_payload: dict[str, Any], threat_payload: dict[str, Any], ai: bool) -> dict[str, Any]:
    """AI thinker runs after scanning, using results as context."""
    context = {
        "os": bloat_payload.get("os", "unknown"),
        "ai_bloat_count": bloat_payload.get("ai_bloat_count", 0),
        "telemetry_count": bloat_payload.get("telemetry_count", 0),
        "service_count": bloat_payload.get("service_count", 0),
        "package_count": bloat_payload.get("package_count", 0),
        "suspicious_processes": threat_payload.get("suspicious_processes", 0),
        "persistence_items": threat_payload.get("persistence_items", 0),
        "indicators": threat_payload.get("indicators", 0),
        "network_connections": threat_payload.get("network_connections", 0),
        "open_ports": threat_payload.get("open_ports", 0),
    }
    thinker = build_thinker(force_llm=ai)
    suggestions = thinker.think(context)
    ai_summary = thinker.summarize([asdict(s) for s in suggestions])
    return {
        "suggestions": [asdict(s) for s in suggestions],
        "ai_summary": ai_summary,
    }


def cmd_audit_bloat(args: argparse.Namespace) -> int:
    try:
        payload = _run_bloat(args.ai)
    except Exception as exc:  # noqa: BLE001
        return handle_error(AuditError("BLOAT_AUDIT_FAILED", str(exc), keywords=["bloat", "audit", "failed"], docs="docs/troubleshooting.md"))
    _write(args.output, payload)
    print(payload.get("summary", ""))
    return 0


def cmd_audit_threat(args: argparse.Namespace) -> int:
    try:
        payload = _run_threat(args.ai, args.paths)
    except Exception as exc:  # noqa: BLE001
        return handle_error(AuditError("THREAT_SCAN_FAILED", str(exc), keywords=["threat", "scan", "failed"], docs="docs/troubleshooting.md"))
    _write(args.output, payload)
    print(payload.get("summary", ""))
    return 0


def cmd_audit_full(args: argparse.Namespace) -> int:
    """Run bloat + threat scans in parallel, then AI thinker."""
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            future_bloat = executor.submit(_run_bloat, args.ai)
            future_threat = executor.submit(_run_threat, args.ai, None)
            bloat_payload = future_bloat.result()
            threat_payload = future_threat.result()

        think_payload = _run_thinker(bloat_payload, threat_payload, args.ai)

        payload = {
            "bloat": bloat_payload,
            "threat": threat_payload,
            "think": think_payload,
        }
    except Exception as exc:  # noqa: BLE001
        return handle_error(AuditError("FULL_AUDIT_FAILED", str(exc), keywords=["full", "audit", "parallel", "failed"], docs="docs/troubleshooting.md"))

    _write(args.output, payload)
    print(bloat_payload.get("summary", ""))
    print(threat_payload.get("summary", ""))
    if think_payload.get("ai_summary"):
        print(f"AI thinker: {think_payload['ai_summary']}")
    print(f"Suggestions: {len(think_payload.get('suggestions', []))}")
    return 0


def cmd_audit_removal(args: argparse.Namespace) -> int:
    """Plan removal first (dry-run, shows everything), then apply only with --apply + confirmation."""
    try:
        bloat_report = None
        if args.bloat_report and Path(args.bloat_report).exists():
            bloat_report = json.loads(Path(args.bloat_report).read_text(encoding="utf-8"))
        else:
            bloat_report = _run_bloat(ai=False)

        engine = RemovalEngine(dry_run=not args.apply)
        planned = engine.plan_from_bloat(bloat_report)

        # Propose fixes: show everything before any change
        print(engine.preview(planned))

        if not planned:
            print("No removable bloat items found.")
            return 0

        if args.apply:
            # Confirmation gate: user must explicitly confirm
            result = engine.apply(planned, confirm=True)
            print(f"Applied: {result.applied}, Skipped: {result.skipped}, Failed: {result.failed}")
            print(f"Log: {result.log_path}")
            print(f"SHA256: {engine.hash_log(result.log_path)}")
        else:
            print("DRY RUN: nothing changed. Re-run with --apply to execute (requires confirmation).")
    except Exception as exc:  # noqa: BLE001
        return handle_error(AuditError("REMOVAL_FAILED", str(exc), keywords=["removal", "apply", "failed"], docs="docs/troubleshooting.md"))
    return 0


def run_audit(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="computer-audit audit", description="Security & bloat audit")
    sub = parser.add_subparsers(dest="audit_cmd", required=True)

    pb = sub.add_parser("bloat", help="Audit bloat / AI bloat")
    pb.add_argument("--output", help="Write JSON report")
    pb.add_argument("--ai", action="store_true", help="AI summary (needs AI_API_BASE/AI_API_KEY)")
    pb.set_defaults(func=cmd_audit_bloat)

    pt = sub.add_parser("threat", help="Threat / trojan triage scan (includes open ports)")
    pt.add_argument("--output", help="Write JSON report")
    pt.add_argument("--paths", nargs="*", help="Extra files to scan for indicators")
    pt.add_argument("--ai", action="store_true", help="AI summary")
    pt.set_defaults(func=cmd_audit_threat)

    pr = sub.add_parser("removal", help="Plan & apply bloat removal")
    pr.add_argument("--bloat-report", help="Existing bloat JSON report")
    pr.add_argument("--output", help="Write removal plan/log JSON")
    pr.add_argument("--apply", action="store_true", help="Execute removal")
    pr.set_defaults(func=cmd_audit_removal)

    pf = sub.add_parser("full", help="Full audit: bloat + threat in parallel, then AI thinker")
    pf.add_argument("--output", help="Write combined JSON report")
    pf.add_argument("--ai", action="store_true", help="AI summary + thinker (needs AI_API_BASE/AI_API_KEY)")
    pf.set_defaults(func=cmd_audit_full)

    args = parser.parse_args(argv)
    return args.func(args)
