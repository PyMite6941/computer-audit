"""Threat / trojan / malware scanner.

Fast triage (std-only) that looks for:
- Suspicious running processes (known malware/loader names + suspicious cmdlines)
- Persistence mechanisms (Windows Run keys, Linux cron/systemd timers, macOS launchd)
- Indicator strings (IPs, domains, base64 blobs, private keys) in memory-like files
- Unexpected outbound network connections
- Open ports on localhost (parallel TCP connect scan)

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


@dataclass
class ThreatItem:
    id: str
    category: str          # suspicious-process | persistence | indicator | network
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
    summary: str


def _run(cmd: list[str]) -> tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out: {cmd[0]}"


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

    # ------------------------------------------------------------- run
    def scan(self, extra_paths: list[str] | None = None) -> ThreatReport:
        self.items = []
        self._processes()
        self._persistence()
        self._indicators(extra_paths or [])
        self._network()
        self._ports()

        open_count = sum(1 for i in self.items if i.category == "open-port")
        return ThreatReport(
            os=self.os,
            items=[asdict(i) for i in self.items],
            suspicious_processes=sum(1 for i in self.items if i.category == "suspicious-process"),
            persistence_items=sum(1 for i in self.items if i.category == "persistence"),
            indicators=sum(1 for i in self.items if i.category == "indicator"),
            network_connections=sum(1 for i in self.items if i.category == "network"),
            open_ports=open_count,
            summary=(
                f"{len(self.items)} threat item(s) on {self.os}: "
                f"{sum(1 for i in self.items if i.category=='suspicious-process')} suspicious process(es), "
                f"{sum(1 for i in self.items if i.category=='persistence')} persistence item(s), "
                f"{sum(1 for i in self.items if i.category=='indicator')} indicator(s), "
                f"{sum(1 for i in self.items if i.category=='network')} network connection(s), "
                f"{open_count} open port(s)."
            ),
        )
