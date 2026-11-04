# computer-audit

Cross-platform security audit toolkit. Three algorithms, AI-enhanceable, zero
mandatory installs on the host (everything runs in a Python venv; npm is
optional and only for a future frontend).

## Domains

| # | Domain | Module | What it does |
|---|--------|--------|--------------|
| 1 | Modern IAM Visualization & Auditing | `core/iam_auditor.py` | Builds permission graphs from cloud IAM dumps, computes blast radius from a compromised identity, surfaces privilege-escalation paths, exports Graphviz DOT + JSON |
| 2 | Automated Threat Hunting & Memory Forensics | `core/forensics.py` | Extracts strings/indicators from memory dumps, parses logs, flags suspicious processes, emits a triage report |
| 3 | API Security & Microservice Scanning | `core/api_scanner.py` | Dynamically discovers endpoints, probes for broken object-level authorization (BOLA) and missing auth |

## AI enhancement

`core/ai_enhancer.py` wraps every algorithm. Default = offline rule-based
heuristics (no network, no API key). Optional LLM backend via:

```sh
export AI_API_BASE=http://localhost:11434/v1   # Ollama / llama.cpp / any OpenAI-compatible endpoint
export AI_API_KEY=sk-optional
export AI_MODEL=llama3
```

Set `AI_API_BASE` + `AI_API_KEY` and pass `--ai` (or `"ai": true` in the web API)
to get LLM-generated summaries, explanations, and remediation steps. Falls back
to rules when the LLM is unreachable.

## Supported OS (non-mobile)

Windows, macOS, Linux. Install:

```sh
# PowerShell (Windows)
.\install.ps1
.\run.ps1 iam
.\run.ps1 web --port 8000

# bash (Linux / macOS / Git-Bash / WSL)
./install.sh
./run.sh iam
./run.sh web
```

npm is checked for but not required; `package.json` is ready for a future
frontend under `web/frontend`.

## GitHub Pages

Documentation is published via GitHub Pages at:
https://pymite6941.github.io/computer-audit/

The `docs/` folder is the Pages source. Deploy workflow lives at
`.github/workflows/deploy-pages.yml` and runs on pushes to `master`.

## Quick demo (no network, no cloud account)

```sh
./run.sh iam --input data/iam_sample.json --compromised user:alice --output reports/iam.json
./run.sh forensics --dump samples/mem.bin --log samples/auth.log --output reports/forensics.json
./run.sh api --target http://127.0.0.1:8000 --output reports/api.json
```

Sample IAM data is generated on first run if `--input` is omitted.

## Files

- `core/` - algorithms (IAM, forensics, API, AI enhancer)
- `cli/main.py` - unified CLI entry point
- `web/app.py` - optional FastAPI web API
- `install.sh` / `install.ps1` - venv + deps setup
- `run.sh` / `run.ps1` - cross-platform launcher
- `requirements.txt` - Python deps (kept minimal)
- `package.json` - npm placeholder for future frontend
