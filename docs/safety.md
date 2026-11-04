# Removal Safety Model

computer-audit removes bloat, AI bloat, and unnecessary services **safely**.

## Guarantees

1. **Dry-run by default** — No system command runs unless you pass `--apply` and confirm.
2. **Confirmation gate** — Every planned action (target, action, risk, shell command) is printed before execution.
3. **NEVER_TOUCH** — OS-critical services (systemd, dbus, ssh, udev, wininit, rpcss, etc.) are never selectable.
4. **Explicit commands** — Every PowerShell / bash / zsh command is logged and shown. No hidden behavior.
5. **Audit logs** — Each removal run writes a SHA-256-hashed JSON log to `reports/removal-<timestamp>.json`.

## What can be removed/disabled

| Category | Examples | Risk |
|----------|----------|------|
| AI bloat | Copilot, Recall/Click to Do, local LLM agents | low–medium |
| Telemetry | DiagTrack, diagnostics, activity history | low |
| Unused services | Xbox services, RetailDemo, dmwappushservice | low |
| Pre-installed apps | Zune, Xbox, Bing Weather, CandyCrush AppX | low |
| Suspicious processes | Mimikatz, netcat, meterpreter (manual kill) | high |

## What is NEVER touched

Windows: rpcss, dcom, wininit, services.
Linux: systemd, dbus, udev, ssh, networkd, journald, login, polkit.

## Reversibility

- Service disables use `Set-Service -StartupType Disabled` / `systemctl disable --now` — reversible by re-enabling.
- AppX removals remove provisioned packages — some can be reinstalled from Microsoft Store.
- Process kills are immediate and not reversible (use only on confirmed malware).

## Running removal

```sh
# 1. Plan (dry-run — safe, shows everything)
python -m cli.main audit removal --output reports/plan.json

# 2. Review reports/plan.json

# 3. Apply (requires confirmation)
python -m cli.main audit removal --apply --output reports/applied.json
```
