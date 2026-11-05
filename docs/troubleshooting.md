# Troubleshooting

Common errors, error codes, and how to fix them. Errors follow a Minecraft-style
format: each has a **code**, **message**, **keywords**, and **docs** reference.

## Error codes

| Code | Meaning | Keywords | Fix |
|------|---------|----------|-----|
| `BLOAT_AUDIT_FAILED` | Bloat detection crashed | bloat, audit, failed | Re-run `./run.sh audit bloat`. Ensure Python venv is active. |
| `THREAT_SCAN_FAILED` | Threat scan crashed | threat, scan, failed | Re-run `./run.sh audit threat`. Check file permissions on scan paths. |
| `REMOVAL_FAILED` | Bloat removal crashed | removal, apply, failed | Run as Administrator (Windows) or sudo (Linux/macOS). |
| `FULL_AUDIT_FAILED` | Parallel audit crashed | full, audit, parallel, failed | Re-run without `--ai` to isolate AI backend issues. |
| `UNEXPECTED_ERROR` | Unhandled exception | error, exception, crash | Check the error message and open a bug report with the code. |
| `PORT_SCAN_FAILED` | Port scanner crashed | port, bind, firewall | Port scan is non-fatal — scan continues without port data. |
| `AI_BACKEND_UNREACHABLE` | LLM thinker/enhancer unreachable | ai, llm, unreachable | Falls back to offline rule-based thinker/enhancer automatically. |

## Port scanning

Open ports on `127.0.0.1` are scanned in parallel (50 workers, 1s timeout per port).
Common ports checked: 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993,
995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017.

Port scan failures are non-fatal — the audit continues without port data.

## AI thinker

The AI thinker (`core/ai_thinker.py`) is separate from the AI enhancer
(`core/ai_enhancer.py`). The enhancer summarizes findings after a scan. The
thinker runs after scanning and suggests what to investigate next.

- Offline rule-based thinker by default.
- Optional LLM backend via `AI_API_BASE` + `AI_API_KEY` + `--ai`.
- Suggestions are advisory only — nothing is changed automatically.

## Removal safety

- **Dry-run by default** — nothing changes until `--apply`.
- **Confirmation gate** — full planned-action list shown before execution.
- **NEVER_TOUCH** — OS-critical services/packages never selected.
- **SHA-256 audit log** — every removal run writes a hashed log to `reports/`.

## Support

Open a bug report with the error code and keywords. Include your OS and the
command you ran.
