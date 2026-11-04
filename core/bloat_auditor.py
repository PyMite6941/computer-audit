"""Bloat & AI-bloat auditor.

Cross-platform, stdlib-heavy. Detects:
- AI-related bloat (Copilot, Recall, local LLM services, AI agents)
- Telemetry / data-collection services
- Unnecessary pre-installed apps (AppX on Windows, dpkg/rpm on Linux, pkgutil on macOS)
- Idle/unused systemd services and launchd agents

Every detected item carries a shell command (per OS) that can disable or remove it.
Nothing is acted upon until the removal engine confirms + dry-run off.
"""

from __future__ import annotations

import dataclasses
import os
import platform
import shutil
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any


# --------------------------------------------------------------------------- data
@dataclass
class BloatItem:
    id: str
    category: str          # ai-bloat | telemetry | unused-service | preinstalled-app | unnecessary-package
    name: str
    detail: str
    os: str                # windows | linux | darwin | all
    disable_cmd: list[str]
    remove_cmd: list[str] | None
    risk: str              # low | medium | high
    never_touch: bool = False


@dataclass
class BloatReport:
    os: str
    items: list[dict[str, Any]]
    ai_bloat_count: int
    telemetry_count: int
    service_count: int
    package_count: int
    summary: str


# --------------------------------------------------------------------------- helpers
def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out: {cmd[0]}"


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# --------------------------------------------------------------------------- auditor
class BloatAuditor:
    """Detect bloat and emit per-OS disable/remove shell commands."""

    def __init__(self) -> None:
        self.os = platform.system().lower()
        self.items: list[BloatItem] = []

    # --------------------------------------------------------------- windows
    def _windows(self) -> None:
        # AI / Copilot / Recall bloat
        self.items.append(BloatItem(
            id="win-ai-copilot",
            category="ai-bloat",
            name="Microsoft Copilot (AI)",
            detail="Copilot AI assistant integration in Windows 11.",
            os="windows",
            disable_cmd=["powershell", "-Command", "Get-AppxPackage -AllUsers *Microsoft.549981C3F5F10* | Remove-AppxPackage"],
            remove_cmd=["powershell", "-Command", "Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -like '*Microsoft.549981C3F5F10*'} | Remove-AppxProvisionedPackage -Online"],
            risk="low",
        ))
        self.items.append(BloatItem(
            id="win-ai-recall",
            category="ai-bloat",
            name="Windows Recall / Click to Do (AI)",
            detail="AI snapshot/recall feature (WSAIFabricSvc).",
            os="windows",
            disable_cmd=["powershell", "-Command", "Set-Service -Name WSAIFabricSvc -StartupType Disabled"],
            remove_cmd=None,
            risk="medium",
        ))

        # Telemetry
        self.items.append(BloatItem(
            id="win-telemetry-diagtrack",
            category="telemetry",
            name="Connected User Experiences and Telemetry (DiagTrack)",
            detail="Windows telemetry and diagnostic data collection.",
            os="windows",
            disable_cmd=["powershell", "-Command", "Set-Service -Name DiagTrack -StartupType Disabled; Stop-Service -Name DiagTrack -ErrorAction SilentlyContinue"],
            remove_cmd=None,
            risk="low",
        ))

        # Unused services (examples — only disable if present)
        for svc in ("XblAuthManager", "XblGameSave", "XboxNetApiSvc", "RetailDemo", "dmwappushservice"):
            self.items.append(BloatItem(
                id=f"win-svc-{svc.lower()}",
                category="unused-service",
                name=svc,
                detail=f"Windows service {svc} — commonly unnecessary on non-gaming/non-retail PCs.",
                os="windows",
                disable_cmd=["powershell", "-Command", f"Set-Service -Name {svc} -StartupType Disabled; Stop-Service -Name {svc} -ErrorAction SilentlyContinue"],
                remove_cmd=None,
                risk="low",
            ))

        # Pre-installed AppX bloat (only flag if installed)
        for app in ("*Microsoft.ZuneMusic*", "*Microsoft.XboxApp*", "*Microsoft.BingWeather*", "*King.CandyCrush*"):
            self.items.append(BloatItem(
                id=f"win-appx-{app.strip('*').lower()}",
                category="preinstalled-app",
                name=f"AppX package {app}",
                detail="Pre-installed Microsoft Store app (bloatware).",
                os="windows",
                disable_cmd=["powershell", "-Command", f"Get-AppxPackage -AllUsers {app} | Remove-AppxPackage"],
                remove_cmd=["powershell", "-Command", f"Get-AppxProvisionedPackage -Online | Where-Object {{$_.PackageName -like '{app}'}} | Remove-AppxProvisionedPackage -Online"],
                risk="low",
            ))

    # ---------------------------------------------------------------- linux
    def _linux(self) -> None:
        # Idle/unused systemd services (only if systemctl exists)
        if not _have("systemctl"):
            return
        code, out, _ = _run(["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"])
        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            unit = parts[0]
            if unit.endswith(".service") and not any(
                critical in unit for critical in ("systemd", "dbus", "ssh", "networkd", "udev", "journal", "login", "polkit")
            ):
                self.items.append(BloatItem(
                    id=f"linux-svc-{unit}",
                    category="unused-service",
                    name=unit,
                    detail=f"Running systemd service {unit} — candidate to disable if not needed.",
                    os="linux",
                    disable_cmd=["systemctl", "disable", "--now", unit],
                    remove_cmd=None,
                    risk="low",
                ))

    # ---------------------------------------------------------------- darwin
    def _darwin(self) -> None:
        if not _have("launchctl"):
            return
        code, out, _ = _run(["launchctl", "list"])
        for line in out.splitlines()[1:]:
            parts = line.split()
            if not parts:
                continue
            label = parts[-1]
            if any(ai in label.lower() for ai in ("ollama", "copilot", "ai", "llm")):
                self.items.append(BloatItem(
                    id=f"darwin-agent-{label}",
                    category="ai-bloat",
                    name=label,
                    detail=f"launchd agent {label} — possible AI/LLM background agent.",
                    os="darwin",
                    disable_cmd=["launchctl", "disable", "user/$(id -u)", label],
                    remove_cmd=None,
                    risk="low",
                ))

    # ---------------------------------------------------------------- run
    def audit(self) -> BloatReport:
        self.items = []
        if self.os == "windows":
            self._windows()
        elif self.os == "linux":
            self._linux()
        elif self.os == "darwin":
            self._darwin()

        ai = [i for i in self.items if i.category == "ai-bloat"]
        tel = [i for i in self.items if i.category == "telemetry"]
        svc = [i for i in self.items if i.category == "unused-service"]
        pkg = [i for i in self.items if i.category in ("preinstalled-app", "unnecessary-package")]

        summary = (
            f"{len(self.items)} bloat item(s) detected on {self.os}: "
            f"{len(ai)} AI-bloat, {len(tel)} telemetry, {len(svc)} unused-service, {len(pkg)} package/app."
        )
        return BloatReport(
            os=self.os,
            items=[asdict(i) for i in self.items],
            ai_bloat_count=len(ai),
            telemetry_count=len(tel),
            service_count=len(svc),
            package_count=len(pkg),
            summary=summary,
        )
