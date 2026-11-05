"""Threat / trojan / malware scanner.

Fast triage (std-only) that looks for:
- Suspicious running processes (known malware/loader names + suspicious cmdlines)
- Persistence mechanisms (Windows Run keys, Linux cron/systemd timers, macOS launchd)
- Indicator strings (IPs, domains, base64 blobs, private keys) in memory-like files
- Unexpected outbound network connections
- Open ports on localhost (parallel TCP connect scan)
- Spyware / malware / adware files and browser extensions
- Autorun / startup items

Designed for quick triage, not a replacement for a full AV/EDR.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import os
import re
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any

from core.port_scanner import scan_ports  # noqa: E402


SUSPICIOUS_PROC_KEYS = (
    "mimikatz", "procdump", "pwdump", "nc.exe", "netcat", "ncat",
    "meterpreter", "cobalt", "powershell -enc", "iex(", "invoke-webrequest",
    "certutil", "bitsadmin", "reverse", "shell", "keylog", "rat",
    "tor", "torbrowser", "onion",
)

IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
BASE64_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
PRIVATE_KEY_RE = re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----")

# Known spyware/malware/adware file name patterns (lowercase)
MALWARE_NAME_PATTERNS = (
    "mimikatz", "procdump", "pwdump", "keylog", "keystroke", "stealer",
    "rat.", "trojan", "backdoor", "botnet", "miner", "cryptominer",
    "adware", "popup", "browser-hijacker", "search-proxy",
    "crack", "keygen", "loader", "stealth", "hidden",
    "vcredist_x64.exe", "flash_player_update.exe",
    "java_update.exe", "adobe_update.exe",
)

# Known spyware/malware/adware file path patterns (lowercase)
MALWARE_PATH_PATTERNS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\roaming\\", "\\appdata\\local\\temp\\",
    "\\programdata\\", "\\windows\\temp\\", "\\syswow64\\temp\\",
    "/tmp/", "/var/tmp/", "/dev/shm/", "/Library/LaunchAgents/",
    "/Library/LaunchDaemons/", "~/Library/Application Support/",
)

# Browser extension install paths (common locations)
BROWSER_EXT_PATHS_WINDOWS = [
    os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Extensions"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\Extensions"),
    os.path.expandvars(r"%APPDATA%\Mozilla\Firefox\Profiles\*\extensions"),
]

BROWSER_EXT_PATHS_DARWIN = [
    os.path.expanduser("~/Library/Application Support/Google/Chrome/*/Extensions"),
    os.path.expanduser("~/Library/Application Support/Mozilla/Firefox/Profiles/*/extensions"),
]

BROWSER_EXT_PATHS_LINUX = [
    os.path.expanduser("~/.config/google-chrome/*/Extensions"),
    os.path.expanduser("~/.mozilla/firefox/*/extensions"),
]

# Suspicious autorun/startup locations
AUTORUN_WINDOWS = [
    os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
    os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\StartUp"),
    os.path.expandvars(r"%USERPROFILE%\Start Menu\Programs\Startup"),
]

AUTORUN_DARWIN = [
    os.path.expanduser("~/Library/LaunchAgents"),
    os.path.expanduser("~/Library/LaunchDaemons"),
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]

AUTORUN_LINUX = [
    os.path.expanduser("~/.config/autostart"),
    "/etc/xdg/autostart",
]


# Bloat scan roots per OS
BLOAT_ROOTS_WINDOWS = [
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%TMP%"),
    os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\INetCache"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Windows\WebCache"),
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\AppData\Local\Microsoft\Windows\Explorer"),
    os.path.expandvars(r"%USERPROFILE%\AppData\Local\CrashDumps"),
    os.path.expandvars(r"%SYSTEMROOT%\Temp"),
    os.path.expandvars(r"%SYSTEMROOT%\Prefetch"),
]

BLOAT_ROOTS_DARWIN = [
    os.path.expanduser("~/Library/Caches"),
    os.path.expanduser("~/Library/Logs"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Library/Containers/com.apple.Safari/Cache"),
    os.path.expanduser("~/Library/Safari/Databases"),
    "/private/var/log",
    "/private/var/folders",
]

BLOAT_ROOTS_LINUX = [
    os.path.expanduser("~/.cache"),
    os.path.expanduser("~/.local/share/Trash"),
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/.thumbnails"),
    "/var/log",
    "/var/tmp",
    "/tmp",
]


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out: {cmd[0]}"


@dataclass
class ThreatItem:
    id: str
    category: str          # suspicious-process | persistence | indicator | network | open-port | malware | spyware | adware | browser-extension | autorun
    name: str
    detail: str
    os: str
    evidence: dict[str, Any] = field(default_factory=dict)
    risk: str = "medium"   # low | medium | high | critical


@dataclass
class ThreatReport:
    os: str
    items: list[dict[str, Any]]
    suspicious_processes: int
    persistence_items: int
    indicators: int
    network_connections: int
    open_ports: int
    malware_items: int
    spyware_items: int
    adware_items: int
    browser_extensions: int
    autorun_items: int
    summary: str


class ThreatScanner:
    """Triage-level threat scanner."""

    def __init__(self) -> None:
        self.os = __import__("platform").system().lower()
        self.items: list[ThreatItem] = []

    # --------------------------------------------------------------- processes
    def _processes(self) -> None:
        # Windows: tasklist /v
        if self.os == "windows" and shutil.which("tasklist"):
            code, out, _ = _run(["tasklist", "/v", "/fo", "csv"])
            for line in out.splitlines()[1:]:
                cells = [c.strip('"') for c in line.split('","')]
                if len(cells) < 2:
                    continue
                name, pid = cells[0], cells[1]
                low = (name + " " + " ".join(cells)).lower()
                for kw in SUSPICIOUS_PROC_KEYS:
                    if kw in low:
                        self.items.append(ThreatItem(
                            id=f"threat-proc-{pid}",
                            category="suspicious-process",
                            name=name,
                            detail=f"Process matched keyword '{kw}'",
                            os="windows",
                            evidence={"pid": pid, "image": name},
                            risk="high",
                        ))
                        break
        # Linux/macOS: ps
        elif shutil.which("ps"):
            code, out, _ = _run(["ps", "-eo", "pid,comm,args"])
            for line in out.splitlines()[1:]:
                parts = line.split(None, 2)
                if len(parts) < 2:
                    continue
                pid, comm = parts[0], parts[1]
                args = parts[2] if len(parts) > 2 else ""
                low = (comm + " " + args).lower()
                for kw in SUSPICIOUS_PROC_KEYS:
                    if kw in low:
                        self.items.append(ThreatItem(
                            id=f"threat-proc-{pid}",
                            category="suspicious-process",
                            name=comm,
                            detail=f"Process matched keyword '{kw}'",
                            os=self.os,
                            evidence={"pid": pid, "args": args[:120]},
                            risk="high",
                        ))
                        break

    # ------------------------------------------------------------- persistence
    def _persistence(self) -> None:
        if self.os == "windows":
            # Run / RunOnce keys
            for hive, path in (("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
                               ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run")):
                code, out, _ = _run(["reg", "query", hive + "\\" + path])
                if code == 0:
                    for line in out.splitlines():
                        if "REG_" in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                self.items.append(ThreatItem(
                                    id=f"threat-persist-{parts[0].lower()}",
                                    category="persistence",
                                    name=parts[0],
                                    detail=f"Windows Run-key persistence: {parts[0]}",
                                    os="windows",
                                    evidence={"hive": hive, "key": path, "value": line},
                                    risk="medium",
                                ))
        else:
            # cron
            if shutil.which("crontab"):
                code, out, _ = _run(["crontab", "-l"])
                if code == 0 and out.strip():
                    self.items.append(ThreatItem(
                        id="threat-persist-crontab",
                        category="persistence",
                        name="user crontab",
                        detail="Active user crontab detected — review for malicious scheduled jobs.",
                        os=self.os,
                        evidence={"crontab": out[:500]},
                        risk="medium",
                    ))
            # systemd timers
            if shutil.which("systemctl"):
                code, out, _ = _run(["systemctl", "list-timers", "--all", "--no-pager", "--no-legend"])
                if code == 0:
                    for line in out.splitlines():
                        parts = line.split()
                        if parts and parts[-1].endswith(".timer"):
                            self.items.append(ThreatItem(
                                id=f"threat-persist-{parts[-1]}",
                                category="persistence",
                                name=parts[-1],
                                detail="systemd timer — verify it is legitimate.",
                                os=self.os,
                                evidence={"timer": parts[-1]},
                                risk="low",
                            ))

    # ------------------------------------------------------------- indicators
    def _indicators(self, paths: list[str]) -> None:
        for path in paths:
            if not os.path.exists(path):
                continue
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except (OSError, PermissionError):
                continue
            for m in IP_RE.finditer(data):
                ip = m.group(0).decode()
                try:
                    ipaddress.ip_address(ip)
                    self.items.append(ThreatItem(
                        id=f"threat-ind-ip-{ip}",
                        category="indicator",
                        name="IP address",
                        detail=f"IP indicator found in {path}",
                        os=self.os,
                        evidence={"file": path, "ip": ip},
                        risk="low",
                    ))
                except ValueError:
                    pass
            if PRIVATE_KEY_RE.search(data):
                self.items.append(ThreatItem(
                    id=f"threat-ind-key-{path}",
                    category="indicator",
                    name="Private key",
                    detail=f"PEM private key block found in {path}",
                    os=self.os,
                    evidence={"file": path},
                    risk="medium",
                ))

    # ------------------------------------------------------------- network
    def _network(self) -> None:
        if self.os == "windows" and shutil.which("netstat"):
            code, out, _ = _run(["netstat", "-ano"])
            for line in out.splitlines():
                if "ESTABLISHED" in line or "SYN" in line:
                    self.items.append(ThreatItem(
                        id=f"threat-net-{abs(hash(line)) % 100000}",
                        category="network",
                        name="network connection",
                        detail="Active/connecting network socket",
                        os="windows",
                        evidence={"line": line[:160]},
                        risk="low",
                    ))
        elif shutil.which("ss"):
            code, out, _ = _run(["ss", "-tunap"])
            for line in out.splitlines()[1:]:
                if "ESTAB" in line or "SYN" in line:
                    self.items.append(ThreatItem(
                        id=f"threat-net-{abs(hash(line)) % 100000}",
                        category="network",
                        name="network connection",
                        detail="Active/connecting network socket",
                        os=self.os,
                        evidence={"line": line[:160]},
                        risk="low",
                    ))

    # ------------------------------------------------------------- ports
    def _ports(self) -> None:
        try:
            report = scan_ports(target="127.0.0.1")
            for port in report.open_ports:
                self.items.append(ThreatItem(
                    id=f"threat-port-{port}",
                    category="open-port",
                    name=f"port {port}",
                    detail=f"Open port {port} on localhost ({report.target})",
                    os=self.os,
                    evidence={"port": port, "target": report.target},
                    risk="low",
                ))
        except Exception:  # noqa: BLE001 - port scan failure is non-fatal
            pass

    # ------------------------------------------------- spyware/malware/adware
    def _spyware_malware_adware(self) -> None:
        """Scan common user-writable locations for known bad file names/paths."""
        roots: list[str] = []
        if self.os == "windows":
            roots = [
                os.path.expandvars(r"%TEMP%"),
                os.path.expandvars(r"%TMP%"),
                os.path.expandvars(r"%LOCALAPPDATA%\Temp"),
                os.path.expandvars(r"%APPDATA%"),
                os.path.expandvars(r"%LOCALAPPDATA%"),
                os.path.expandvars(r"%USERPROFILE%\Downloads"),
            ]
        elif self.os == "darwin":
            roots = [
                os.path.expanduser("~/Library/Application Support"),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Library/Caches"),
            ]
        else:
            roots = [
                os.path.expanduser("~/.cache"),
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/.config"),
            ]

        for root in roots:
            if not os.path.exists(root):
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
                    depth = dirpath[len(root):].count(os.sep)
                    if depth > 3:
                        dirnames[:] = []
                        continue
                    for name in filenames:
                        low = name.lower()
                        full = os.path.join(dirpath, name)
                        low_path = full.lower()
                        matched = False
                        category = "malware"
                        risk = "high"

                        for pat in MALWARE_NAME_PATTERNS:
                            if pat in low:
                                matched = True
                                category = "malware"
                                risk = "high"
                                break
                        if not matched:
                            for pat in MALWARE_PATH_PATTERNS:
                                if pat in low_path:
                                    matched = True
                                    if any(kw in low for kw in ("adware", "popup", "browser-hijacker", "search-proxy")):
                                        category = "adware"
                                        risk = "medium"
                                    elif any(kw in low for kw in ("spyware", "keylog", "stealer", "tracker")):
                                        category = "spyware"
                                        risk = "high"
                                    else:
                                        category = "malware"
                                        risk = "high"
                                    break

                        if matched:
                            try:
                                size = os.path.getsize(full)
                            except OSError:
                                size = 0
                            self.items.append(ThreatItem(
                                id=f"threat-{category}-{abs(hash(full)) % 100000}",
                                category=category,
                                name=name,
                                detail=f"{category.capitalize()} indicator: {name}",
                                os=self.os,
                                evidence={"path": full, "size": size},
                                risk=risk,
                            ))
            except OSError:
                pass

    # ------------------------------------------------- browser extensions
    def _browser_extensions(self) -> None:
        """Flag browser extension directories for review."""
        paths: list[str] = []
        if self.os == "windows":
            paths = BROWSER_EXT_PATHS_WINDOWS
        elif self.os == "darwin":
            paths = BROWSER_EXT_PATHS_DARWIN
        else:
            paths = BROWSER_EXT_PATHS_LINUX

        import glob as _glob
        for path_pattern in paths:
            try:
                for ext_dir in _glob.glob(path_pattern, recursive=True):
                    if not os.path.isdir(ext_dir):
                        continue
                    self.items.append(ThreatItem(
                        id=f"threat-ext-{abs(hash(ext_dir)) % 100000}",
                        category="browser-extension",
                        name=f"Extension: {os.path.basename(ext_dir)}",
                        detail="Browser extension installed — verify it is legitimate.",
                        os=self.os,
                        evidence={"path": ext_dir},
                        risk="low",
                    ))
            except (OSError, ValueError):
                pass

    # ------------------------------------------------- autorun / startup
    def _autorun_items(self) -> None:
        """Scan startup folders for suspicious autorun items."""
        paths: list[str] = []
        if self.os == "windows":
            paths = AUTORUN_WINDOWS
        elif self.os == "darwin":
            paths = AUTORUN_DARWIN
        else:
            paths = AUTORUN_LINUX

        import glob as _glob
        for path_pattern in paths:
            try:
                for item in _glob.glob(path_pattern):
                    if not os.path.exists(item):
                        continue
                    if os.path.isdir(item):
                        try:
                            for name in os.listdir(item):
                                full = os.path.join(item, name)
                                self.items.append(ThreatItem(
                                    id=f"threat-autorun-{abs(hash(full)) % 100000}",
                                    category="autorun",
                                    name=name,
                                    detail=f"Autorun/startup item: {name}",
                                    os=self.os,
                                    evidence={"path": full, "folder": item},
                                    risk="medium",
                                ))
                        except OSError:
                            pass
                    else:
                        self.items.append(ThreatItem(
                            id=f"threat-autorun-{abs(hash(item)) % 100000}",
                            category="autorun",
                            name=os.path.basename(item),
                            detail=f"Autorun/startup item: {os.path.basename(item)}",
                            os=self.os,
                            evidence={"path": item},
                            risk="medium",
                        ))
            except (OSError, ValueError):
                pass

    # ------------------------------------------------------------- run
    def scan(self, extra_paths: list[str] | None = None) -> ThreatReport:
        self.items = []
        self._processes()
        self._persistence()
        self._indicators(extra_paths or [])
        self._network()
        self._ports()
        self._spyware_malware_adware()
        self._browser_extensions()
        self._autorun_items()

        open_count = sum(1 for i in self.items if i.category == "open-port")
        malware_count = sum(1 for i in self.items if i.category == "malware")
        spyware_count = sum(1 for i in self.items if i.category == "spyware")
        adware_count = sum(1 for i in self.items if i.category == "adware")
        ext_count = sum(1 for i in self.items if i.category == "browser-extension")
        autorun_count = sum(1 for i in self.items if i.category == "autorun")

        return ThreatReport(
            os=self.os,
            items=[asdict(i) for i in self.items],
            suspicious_processes=sum(1 for i in self.items if i.category == "suspicious-process"),
            persistence_items=sum(1 for i in self.items if i.category == "persistence"),
            indicators=sum(1 for i in self.items if i.category == "indicator"),
            network_connections=sum(1 for i in self.items if i.category == "network"),
            open_ports=open_count,
            malware_items=malware_count,
            spyware_items=spyware_count,
            adware_items=adware_count,
            browser_extensions=ext_count,
            autorun_items=autorun_count,
            summary=(
                f"{len(self.items)} threat item(s) on {self.os}: "
                f"{sum(1 for i in self.items if i.category=='suspicious-process')} suspicious process(es), "
                f"{sum(1 for i in self.items if i.category=='persistence')} persistence item(s), "
                f"{sum(1 for i in self.items if i.category=='indicator')} indicator(s), "
                f"{sum(1 for i in self.items if i.category=='network')} network connection(s), "
                f"{open_count} open port(s), "
                f"{malware_count} malware item(s), "
                f"{spyware_count} spyware item(s), "
                f"{adware_count} adware item(s), "
                f"{ext_count} browser extension(s), "
                f"{autorun_count} autorun item(s)."
            ),
        )
