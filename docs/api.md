# Web API

Launch: `python -m cli.main web` → http://127.0.0.1:8000

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /health | Health check |
| POST | /audit/bloat | Bloat / AI-bloat audit |
| POST | /audit/threat | Threat / trojan triage |
| POST | /audit/full | Combined bloat + threat |
| POST | /audit/removal | Plan removal (dry-run) |
| POST | /audit/removal/apply | Apply removal (confirmation required) |
| GET | /graph/iam | IAM graph DOT (original module) |
| POST | /ai/explain | AI explanation of a finding |

## Example (curl)

```sh
curl -X POST http://127.0.0.1:8000/audit/bloat -H 'Content-Type: application/json' -d '{}'
curl -X POST http://127.0.0.1:8000/audit/threat -H 'Content-Type: application/json' -d '{}'
curl -X POST http://127.0.0.1:8000/audit/removal -H 'Content-Type: application/json' -d '{"apply": false}'
```

AI explanation requires `AI_API_BASE` + `AI_API_KEY`; otherwise falls back to
offline rule-based heuristics.
