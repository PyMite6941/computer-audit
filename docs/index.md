---
layout: default
title: computer-audit
---

# computer-audit Documentation

Security & bloat audit toolkit — IAM visualization, threat hunting forensics,
API security scanning, and bloat/AI-bloat removal with TUI and Web UI.

## Quick Start

```sh
# Windows (PowerShell)
.\install.ps1
.\run.ps1 audit bloat --output reports/bloat.json

# Linux / macOS / Git-Bash / WSL
./install.sh
./run.sh audit full --output reports/full.json
```

## Interfaces

| Interface | Command | Description |
|-----------|---------|-------------|
| TUI | `python -m tui.app` | Full-screen keyboard-driven audit/review/apply |
| Web UI | `python -m cli.main web` | Browser dashboard at http://127.0.0.1:8000 |
| CLI | `python -m cli.main audit <cmd>` | Scriptable audit commands |

## Audit Commands

```
audit bloat        Detect bloat / AI bloat (Copilot, telemetry, unused services)
audit threat       Threat / trojan triage scan (processes, persistence, network)
audit removal      Plan removal (dry-run) or apply with --apply
audit full         Combined bloat + threat audit
```

## Safety

- **Dry-run by default** — nothing changes until `--apply` + confirmation.
- **Confirmation gate** — full action list shown before execution.
- **NEVER_TOUCH** — OS-critical services/packages never selected.
- **Explicit shell commands** — every PowerShell/bash/zsh command logged.

## AI Enhancement

Optional LLM summaries via `AI_API_BASE` + `AI_API_KEY` + `--ai`. Falls back
to offline rule-based heuristics when unavailable.

## Supported OS

Windows, macOS, Linux (non-mobile). Runs in a Python venv — nothing installed
directly on the host. npm optional for future frontend.

## Audit Modules

- `core/bloat_auditor.py` — bloat & AI-bloat detection
- `core/threat_scanner.py` — threat / trojan triage
- `core/removal_engine.py` — safe removal engine
- `core/ai_enhancer.py` — AI enhancement layer (offline by default)
- `core/iam_auditor.py` — IAM blast radius (original)
- `core/forensics.py` — memory forensics (original)
- `core/api_scanner.py` — API security scanner (original)
