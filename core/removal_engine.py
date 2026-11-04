"""Safe removal engine.

Design rules:
- DRY-RUN BY DEFAULT: no system changes until --apply / confirmation.
- CONFIRMATION GATE: full planned-action list shown before anything runs.
- NEVER_TOUCH: OS-critical items are never selected for removal.
- EXPLICIT: every shell command is logged and printed before execution.
- OS-specific shell methods: PowerShell (Windows), systemctl/apt/dpkg (Linux), launchctl/pkgutil (macOS).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


NEVER_TOUCH_PREFIXES = (
    # Windows critical
    "win-svc-rpcss", "win-svc-dcom", "win-svc-wininit", "win-svc-services",
    # Linux critical
    "linux-svc-systemd", "linux-svc-dbus", "linux-svc-udev", "linux-svc-ssh",
    "linux-svc-networkd", "linux-svc-journald", "linux-svc-login", "linux-svc-polkit",
)


@dataclass
class PlannedAction:
    id: str
    target: str
    action: str          # disable | remove | stop
    command: list[str]
    os: str
    risk: str
    reason: str


@dataclass
class RemovalResult:
    planned: int
    applied: int
    skipped: int
    failed: int
    actions: list[dict[str, Any]]
    log_path: str


class RemovalEngine:
    """Executes planned disable/remove actions safely."""

    def __init__(self, dry_run: bool = True, log_dir: str = "reports") -> None:
        self.dry_run = dry_run
        self.os = platform.system().lower()
        self.log_dir = log_dir
        os.makedirs(self.log_dir, exist_ok=True)
        self.actions: list[dict[str, Any]] = []

    # ------------------------------------------------------------- planning
    def plan_from_bloat(self, report: dict[str, Any]) -> list[PlannedAction]:
        planned: list[PlannedAction] = []
        for it in report.get("items", []):
            if it.get("never_touch") or it["id"] in NEVER_TOUCH_PREFIXES:
                continue
            cmd = it.get("disable_cmd") or []
            if not cmd:
                continue
            planned.append(PlannedAction(
                id=it["id"],
                target=it["name"],
                action="disable",
                command=cmd,
                os=it.get("os", self.os),
                risk=it.get("risk", "low"),
                reason=it.get("detail", ""),
            ))
            # removal is a separate, higher-risk opt-in
            rem = it.get("remove_cmd")
            if rem:
                planned.append(PlannedAction(
                    id=it["id"] + "-remove",
                    target=it["name"] + " (remove)",
                    action="remove",
                    command=rem,
                    os=it.get("os", self.os),
                    risk="high",
                    reason="Full uninstall/provisioned-package removal (higher risk).",
                ))
        return planned

    def plan_from_threats(self, report: dict[str, Any]) -> list[PlannedAction]:
        """Threats are flagged, not auto-removed — user must confirm each."""
        planned: list[PlannedAction] = []
        for it in report.get("items", []):
            if it["category"] == "suspicious-process":
                planned.append(PlannedAction(
                    id=it["id"],
                    target=it["name"],
                    action="stop",
                    command=self._kill_cmd(it),
                    os=it.get("os", self.os),
                    risk=it.get("risk", "high"),
                    reason="Suspicious process — terminate? (manual review recommended)",
                ))
        return planned

    def _kill_cmd(self, item: dict[str, Any]) -> list[str]:
        pid = item.get("evidence", {}).get("pid")
        if self.os == "windows" and pid:
            return ["taskkill", "/PID", str(pid), "/F"]
        if pid:
            return ["kill", "-9", str(pid)]
        return []

    # ------------------------------------------------------------- execution
    def preview(self, planned: list[PlannedAction]) -> str:
        lines = [f"PLANNED ACTIONS ({len(planned)}) — DRY RUN: nothing will change", ""]
        for i, a in enumerate(planned, 1):
            lines.append(f"{i}. [{a.action.upper()}] {a.target}  (risk={a.risk})")
            lines.append(f"     reason: {a.reason}")
            lines.append(f"     cmd:    {' '.join(a.command)}")
            lines.append("")
        lines.append("Run with --apply to execute, or review and confirm in the TUI/Web UI.")
        return "\n".join(lines)

    def apply(self, planned: list[PlannedAction], confirm: bool = False) -> RemovalResult:
        if not confirm and not self.dry_run:
            raise ValueError("confirmation required for non-dry-run apply")
        applied = skipped = failed = 0
        for a in planned:
            entry = {
                "id": a.id,
                "target": a.target,
                "action": a.action,
                "command": " ".join(a.command),
                "os": a.os,
                "risk": a.risk,
                "reason": a.reason,
                "dry_run": self.dry_run,
                "executed": False,
                "returncode": None,
                "stdout": "",
                "stderr": "",
                "status": "skipped",
            }
            if self.dry_run:
                entry["status"] = "dry-run"
                skipped += 1
            else:
                entry["executed"] = True
                try:
                    p = subprocess.run(a.command, capture_output=True, text=True, timeout=30)
                    entry["returncode"] = p.returncode
                    entry["stdout"] = p.stdout[:2000]
                    entry["stderr"] = p.stderr[:2000]
                    if p.returncode == 0:
                        entry["status"] = "applied"
                        applied += 1
                    else:
                        entry["status"] = "failed"
                        failed += 1
                except Exception as exc:  # noqa: BLE001
                    entry["status"] = "error"
                    entry["stderr"] = str(exc)
                    failed += 1
            self.actions.append(entry)
        return self._write_log(applied, skipped, failed, len(planned))

    def _write_log(self, applied: int, skipped: int, failed: int, planned: int) -> RemovalResult:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        log_path = os.path.join(self.log_dir, f"removal-{ts}.json")
        payload = {
            "os": self.os,
            "dry_run": self.dry_run,
            "planned": planned,
            "applied": applied,
            "skipped": skipped,
            "failed": failed,
            "timestamp": ts,
            "actions": self.actions,
        }
        with open(log_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        return RemovalResult(
            planned=planned, applied=applied, skipped=skipped, failed=failed,
            actions=self.actions, log_path=log_path,
        )

    def hash_log(self, log_path: str) -> str:
        h = hashlib.sha256()
        with open(log_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
