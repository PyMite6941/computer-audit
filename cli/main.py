"""Unified CLI for computer-audit.

Usage:
  python -m cli.main iam --input data/iam_sample.json --compromised user:alice
  python -m cli.main forensics --dump mem.bin --log auth.log
  python -m cli.main api --target http://127.0.0.1:8000
  python -m cli.main web                    # launch the web UI/API
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running both as `python -m cli.main` and `python cli/main.py`
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.ai_enhancer import build_enhancer  # noqa: E402
from core.api_scanner import APIScanner  # noqa: E402
from core.audit_cmd import run_audit  # noqa: E402
from core.bloat_auditor import BloatAuditor  # noqa: E402
from core.forensics import Forensics  # noqa: E402
from core.iam_auditor import IAMAuditor, load_sample_dump  # noqa: E402
from core.removal_engine import RemovalEngine  # noqa: E402
from core.threat_scanner import ThreatScanner  # noqa: E402


def _write_output(path: str | None, payload: object) -> None:
    text = json.dumps(payload, indent=2, default=str)
    if path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"Wrote {path}")
    else:
        print(text)


def cmd_iam(args: argparse.Namespace) -> int:
    auditor = IAMAuditor()
    if args.input:
        auditor.load_dump(args.input)
    else:
        sample = load_sample_dump()
        tmp = Path("data/iam_sample.json")
        tmp.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(sample, indent=2), encoding="utf-8")
        auditor.load_dump(str(tmp))
        print(f"No --input given; using generated sample at {tmp}")

    identity = args.compromised or "user:alice"
    radius = auditor.compute_blast_radius(identity)
    enhancer = build_enhancer(force_llm=args.ai)

    result = auditor.to_json(radius)
    result["ai_summary"] = enhancer.summarize(result["findings"], "iam")
    for f in result["findings"]:
        f["ai_explain"] = enhancer.explain(f, "iam")
        f["ai_remediate"] = enhancer.remediate(f, "iam")

    _write_output(args.output, result)

    # human summary
    print(f"\nIAM blast radius for {identity}:")
    print(f"  reachable roles:   {', '.join(radius.reachable_roles) or '-'}")
    print(f"  reachable resources: {', '.join(radius.reachable_resources) or '-'}")
    print(f"  sensitive:          {', '.join(radius.sensitive_resources) or '-'}")
    print(f"  escalation paths:   {len(radius.escalation_paths)}")
    dot = auditor.to_dot(radius)
    Path("reports/iam_graph.dot").parent.mkdir(parents=True, exist_ok=True)
    Path("reports/iam_graph.dot").write_text(dot, encoding="utf-8")
    print("  graph written to reports/iam_graph.dot")
    return 0


def cmd_forensics(args: argparse.Namespace) -> int:
    fr = Forensics()
    proclist = []
    if args.processes:
        proclist = json.loads(Path(args.processes).read_text(encoding="utf-8"))
    report = fr.triage(dump_path=args.dump, log_path=args.log, proclist=proclist)
    enhancer = build_enhancer(force_llm=args.ai)
    payload = {
        "summary": report.summary,
        "ai_summary": enhancer.summarize(
            [{"title": "triage", "detail": report.summary, "severity": "medium"}], "forensics"
        ),
        "indicators": report.indicators,
        "suspicious_processes": report.suspicious_processes,
        "log_hits": report.log_hits,
    }
    _write_output(args.output, payload)
    print(report.summary)
    return 0


def cmd_api(args: argparse.Namespace) -> int:
    scanner = APIScanner(timeout=args.timeout)
    result = scanner.scan(args.target)
    enhancer = build_enhancer(force_llm=args.ai)
    result["ai_summary"] = enhancer.summarize(result["findings"], "api")
    _write_output(args.output, result)
    print(f"Endpoints discovered: {result['endpoints_discovered']}")
    print(f"Findings: {len(result['findings'])}")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print("FastAPI/uvicorn not installed. Run: pip install -r requirements.txt", file=sys.stderr)
        return 1
    from web.app import build_app

    app = build_app()
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="computer-audit", description="Security audit toolkit (IAM, forensics, API).")
    sub = parser.add_subparsers(dest="command", required=True)

    p_iam = sub.add_parser("iam", help="IAM visualization & blast-radius auditing")
    p_iam.add_argument("--input", help="IAM dump JSON path")
    p_iam.add_argument("--compromised", help="Identity to start blast radius from")
    p_iam.add_argument("--output", help="Write JSON report to this file")
    p_iam.add_argument("--ai", action="store_true", help="Enable AI enhancement (needs AI_API_BASE/AI_API_KEY)")
    p_iam.set_defaults(func=cmd_iam)

    p_for = sub.add_parser("forensics", help="Threat hunting & memory forensics triage")
    p_for.add_argument("--dump", help="Memory dump file path")
    p_for.add_argument("--log", help="Log file path")
    p_for.add_argument("--processes", help="JSON process list file path")
    p_for.add_argument("--output", help="Write JSON report to this file")
    p_for.add_argument("--ai", action="store_true", help="Enable AI enhancement")
    p_for.set_defaults(func=cmd_forensics)

    p_api = sub.add_parser("api", help="API security & microservice scanning")
    p_api.add_argument("--target", required=True, help="Target base URL")
    p_api.add_argument("--timeout", type=int, default=8, help="Request timeout seconds")
    p_api.add_argument("--output", help="Write JSON report to this file")
    p_api.add_argument("--ai", action="store_true", help="Enable AI enhancement")
    p_api.set_defaults(func=cmd_api)

    p_audit = sub.add_parser("audit", help="Security & bloat audit (bloat / threat / removal / full)")
    # register audit sub-subparsers so `python -m cli.main audit bloat ...` works
    audit_sub = p_audit.add_subparsers(dest="audit_cmd", required=True)

    apb = audit_sub.add_parser("bloat", help="Audit bloat / AI bloat")
    apb.add_argument("--output", help="Write JSON report")
    apb.add_argument("--ai", action="store_true", help="AI summary")
    apb.set_defaults(func=lambda args: run_audit(["bloat"] + _audit_args(args)))

    apt = audit_sub.add_parser("threat", help="Threat / trojan triage scan (includes open ports)")
    apt.add_argument("--output", help="Write JSON report")
    apt.add_argument("--paths", nargs="*", help="Extra files to scan")
    apt.add_argument("--ai", action="store_true", help="AI summary")
    apt.set_defaults(func=lambda args: run_audit(["threat"] + _audit_args(args)))

    aps = audit_sub.add_parser("storage", help="Storage bloat scan (temp, cache, old downloads, duplicates)")
    aps.add_argument("--output", help="Write JSON report")
    aps.add_argument("--ai", action="store_true", help="AI summary")
    aps.set_defaults(func=lambda args: run_audit(["storage"] + _audit_args(args)))

    apr = audit_sub.add_parser("removal", help="Plan & apply bloat removal")
    apr.add_argument("--bloat-report", help="Existing bloat JSON report")
    apr.add_argument("--output", help="Write removal plan/log JSON")
    apr.add_argument("--apply", action="store_true", help="Execute removal")
    apr.set_defaults(func=lambda args: run_audit(["removal"] + _audit_args(args)))

    apf = audit_sub.add_parser("full", help="Full audit: bloat + threat in parallel, then AI thinker")
    apf.add_argument("--output", help="Write JSON report")
    apf.add_argument("--ai", action="store_true", help="AI summary + thinker (needs AI_API_BASE/AI_API_KEY)")
    apf.set_defaults(func=lambda args: run_audit(["full"] + _audit_args(args)))

    p_web = sub.add_parser("web", help="Launch web UI / API")
    p_web.add_argument("--host", default="127.0.0.1")
    p_web.add_argument("--port", type=int, default=8000)
    p_web.set_defaults(func=cmd_web)

    return parser


def _audit_args(args: argparse.Namespace) -> list[str]:
    """Forward only known audit flags (drop the parser-internal 'func')."""
    skip = {"func", "command", "audit_cmd"}
    out: list[str] = []
    for k, v in vars(args).items():
        if k in skip or v is None:
            continue
        if isinstance(v, bool):
            if v:
                out.append(f"--{k.replace('_', '-')}")
        elif isinstance(v, (list, tuple)):
            for item in v:
                out.extend([f"--{k.replace('_', '-')}", str(item)])
        else:
            out.extend([f"--{k.replace('_', '-')}", str(v)])
    return out


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
