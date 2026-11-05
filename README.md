# computer-audit

Cross-platform security & bloat audit toolkit. IAM visualization, threat
hunting forensics, API security scanning, bloat/AI-bloat removal, open-port
scanning, and AI thinker — with TUI and Web UI. Zero mandatory installs on the
host (everything runs in a Python venv; npm is optional for a future frontend).

## Domains

| # | Domain | Module | What it does |
|---|--------|--------|--------------|
| 1 | Modern IAM Visualization & Auditing | `core/iam_auditor.py` | Builds permission graphs from cloud IAM dumps, computes blast radius from a compromised identity, surfaces privilege-escalation paths, exports Graphviz DOT + JSON |
| 2 | Automated Threat Hunting & Memory Forensics | `core/forensics.py` | Extracts strings/indicators from memory dumps, parses logs, flags suspicious processes, emits a triage report |
| 3 | API Security & Microservice Scanning | `core/api_scanner.py` | Dynamically discovers endpoints, probes for broken object-level authorization (BOLA) and missing auth |
| 4 | Bloat & AI-Bloat Auditing | `core/bloat_auditor.py` | Detects Copilot, Recall, telemetry, unused services, pre-installed AppX apps; emits per-OS disable/remove shell commands |
| 5 | Threat & Trojan Scanning | `core/threat_scanner.py` | Suspicious processes, persistence, indicators, network connections, **open ports**, **spyware/malware/adware**, browser extensions, autorun items |
| 6 | Storage Bloat Scanning | `core/storage_scanner.py` | Parallel scan of temp, cache, old downloads, large unused files, duplicates across all storage |
| 7 | Safe Removal Engine | `core/removal_engine.py` | Dry-run by default, confirmation gate, NEVER_TOUCH list, SHA-256 audit logs, file deletion |

## AI enhancement

`core/ai_enhancer.py` wraps every algorithm. Default = offline rule-based
heuristics (no network, no API key). Optional LLM backend via:

```sh
export AI_API_BASE=http://localhost:11434/v1   # Ollama / llama.cpp / any OpenAI-compatible endpoint
export AI_API_KEY=sk-optional
export AI_MODEL=llama3
```

## AI enhancement & AI thinker (two separate modules)

`core/ai_enhancer.py` summarizes findings after an audit runs.
`core/ai_thinker.py` runs after scanning and suggests what to investigate next.
Both are offline rule-based by default. Optional LLM backend via:

```sh
export AI_API_BASE=http://localhost:11434/v1   # Ollama / llama.cpp / any OpenAI-compatible endpoint
export AI_API_KEY=sk-optional
export AI_MODEL=llama3
```

Pass `--ai` to enable LLM-generated summaries/suggestions. Falls back to rules
when the LLM is unreachable.

## Interfaces

| Interface | Command | Description |
|-----------|---------|-------------|
| TUI | `python -m tui.app` | Full-screen keyboard-driven audit/review/apply |
| Web UI | `python -m cli.main web` | Browser dashboard at http://127.0.0.1:8000 |
| CLI | `python -m cli.main audit <cmd>` | Scriptable audit commands |

## Audit Commands

```
audit bloat        Detect bloat / AI bloat (Copilot, telemetry, unused services)
audit threat       Threat / trojan triage scan (processes, persistence, network, open ports, spyware/malware/adware)
audit storage      Storage bloat scan (temp, cache, old downloads, duplicates, large unused files)
audit removal      Plan removal (dry-run) or apply with --apply
audit full         Combined bloat + threat + storage in parallel, then AI thinker
```

## Removal safety

- **Dry-run by default** — nothing changes until `--apply`.
- **Confirmation gate** — full planned-action list shown before execution.
- **NEVER_TOUCH** — OS-critical services/packages and file system paths never selected.
- **SHA-256 audit log** — every removal run writes a hashed log to `reports/`.
- **File deletion** — storage bloat files are deleted directly (not via shell), with NEVER_TOUCH_PATHS protection.

## Storage scanning

Scans common bloat locations per OS:
- **Windows**: %TEMP%, %TMP%, INetCache, WebCache, Downloads, CrashDumps, Prefetch
- **macOS**: ~/Library/Caches, ~/Library/Logs, ~/Downloads, Safari caches, /var/log
- **Linux**: ~/.cache, ~/.local/share/Trash, ~/Downloads, ~/.thumbnails, /var/log, /tmp

Finds: temp files, cache files, old logs, old downloads, large unused files (>100MB, >90 days), duplicate files (by hash), empty folders.

Runs in parallel (4 workers per root) for speed.

## Supported OS (non-mobile)

Windows, macOS, Linux. Install:

```sh
# PowerShell (Windows)
.\install.ps1
.\run.ps1 audit full
.\run.ps1 tui
.\run.ps1 web --port 8000

# bash (Linux / macOS / Git-Bash / WSL)
./install.sh
./run.sh audit full
./run.sh tui
./run.sh web
```

npm is checked for but not required; `package.json` is ready for a future
frontend under `web/frontend`.

## GitHub Pages

Documentation is published via GitHub Pages at:
https://pymite6941.github.io/computer-audit/

The `docs/` folder is the Pages source. Deploy workflow lives at
`.github/workflows/deploy-pages.yml` and runs on pushes to `master`.

## Error handling

Errors follow a Minecraft-style format: each has a **code**, **message**,
**keywords**, and **docs** reference. See `docs/troubleshooting.md`.

## Quick demo (no network, no cloud account)

```sh
./run.sh audit bloat --output reports/bloat.json
./run.sh audit threat --output reports/threat.json
./run.sh audit full --output reports/full.json
./run.sh audit removal --output reports/removal_plan.json
```

## Files

- `core/` — algorithms (IAM, forensics, API, bloat, threat, port scanner, removal, AI enhancer, AI thinker, errors)
- `cli/main.py` — unified CLI entry point
- `tui/app.py` — full-screen terminal UI
- `web/app.py` — optional FastAPI web API
- `docs/` — GitHub Pages documentation
- `install.sh` / `install.ps1` — venv + deps setup
- `run.sh` / `run.ps1` — cross-platform launcher
- `requirements.txt` — Python deps (kept minimal)
- `package.json` — npm placeholder for future frontend
