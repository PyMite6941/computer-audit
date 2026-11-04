"""Automated Threat Hunting & Memory Forensics.

Fast triage toolkit:
- parse text logs (JSON lines / syslog-ish)
- extract printable strings + indicators from a binary memory dump
- flag suspicious processes and artifacts
- emit a JSON triage report

Designed for speed during incident response; no heavy dependencies.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass, field
from typing import Any

INDICATOR_RE = re.compile(rb"[\x20-\x7E]{4,}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(rb"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
AWS_KEY_RE = re.compile(rb"\b[A-Z0-9]{20}\b")
PRIVATE_KEY_RE = re.compile(rb"-----BEGIN [A-Z ]+PRIVATE KEY-----")
BASE64_BLOB_RE = re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}")
SUSPICIOUS_PROC_KEYS = (
    "mimikatz",
    "procdump",
    "pwdump",
    "nc.exe",
    "netcat",
    "ncat",
    "meterpreter",
    "cobalt",
    "powershell -enc",
    "iex(",
    "invoke-webrequest",
    "certutil",
    "bitsadmin",
)

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Indicator:
    type: str
    value: str
    source: str


@dataclass
class TriageReport:
    dump_path: str
    log_path: str | None
    indicators: list[dict[str, Any]]
    suspicious_processes: list[dict[str, Any]]
    log_hits: list[dict[str, Any]]
    summary: str


class Forensics:
    """Memory-dump and log triage."""

    def __init__(self) -> None:
        self.indicators: list[Indicator] = []

    # ------------------------------------------------------------- memory dump
    def strings_from_dump(self, path: str, min_len: int = 6) -> list[str]:
        """Extract printable strings from a binary file without loading it all."""
        found: list[str] = []
        buf = bytearray()
        chunk = 64 * 1024
        carry = bytearray()
        with open(path, "rb") as fh:
            while True:
                data = fh.read(chunk)
                if not data:
                    break
                data = carry + data
                for match in INDICATOR_RE.finditer(data):
                    s = match.group(0)
                    if len(s) >= min_len:
                        found.append(s.decode("ascii", errors="ignore"))
                carry = data[-min_len:]
        return found

    def extract_indicators(self, text: str, source: str) -> list[Indicator]:
        found: list[Indicator] = []
        for ip in IP_RE.findall(text.encode()):
            try:
                ipaddress.ip_address(ip.decode())
                found.append(Indicator("ip", ip.decode(), source))
            except ValueError:
                pass
        for dom in DOMAIN_RE.findall(text.encode()):
            found.append(Indicator("domain", dom.decode(), source))
        for key in AWS_KEY_RE.findall(text.encode()):
            found.append(Indicator("aws_key", key.decode(), source))
        if PRIVATE_KEY_RE.search(text.encode()):
            found.append(Indicator("private_key", "PEM private key block", source))
        for blob in BASE64_BLOB_RE.findall(text.encode()):
            found.append(Indicator("base64_blob", blob.decode()[:80], source))
        return found

    def analyze_dump(self, path: str) -> list[Indicator]:
        self.indicators = []
        strings = self.strings_from_dump(path)
        joined = "\n".join(strings)
        self.indicators.extend(self.extract_indicators(joined, path))
        # keyword hits
        for kw in ("password", "secret", "token", "credential", "key="):
            for s in strings:
                if kw in s.lower():
                    self.indicators.append(Indicator("keyword", f"{kw}: {s[:60]}", path))
        return self.indicators

    # ---------------------------------------------------------------- logs
    def parse_logs(self, path: str) -> list[dict[str, Any]]:
        hits: list[dict[str, Any]] = []
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                entry: dict[str, Any] = {"line": lineno, "raw": line}
                try:
                    entry["parsed"] = json.loads(line)
                except json.JSONDecodeError:
                    entry["parsed"] = None
                low = line.lower()
                if any(kw in low for kw in ("failed", "error", "exception", "unauthorized", "403", "500")):
                    entry["flag"] = "error-or-failure"
                    hits.append(entry)
                if any(kw in low for kw in ("sudo", "su ", "runas", "admin")):
                    entry["flag"] = "privilege-use"
                    hits.append(entry)
        return hits

    def suspicious_processes(self, proclist: list[dict[str, str]]) -> list[dict[str, str]]:
        flagged: list[dict[str, str]] = []
        for proc in proclist:
            name = (proc.get("name", "") + " " + proc.get("cmdline", "")).lower()
            for kw in SUSPICIOUS_PROC_KEYS:
                if kw in name:
                    flagged.append({**proc, "reason": f"matched keyword: {kw}"})
                    break
        return flagged

    # ---------------------------------------------------------------- report
    def triage(self, dump_path: str | None = None, log_path: str | None = None,
               proclist: list[dict[str, str]] | None = None) -> TriageReport:
        inds: list[Indicator] = []
        if dump_path and os.path.exists(dump_path):
            inds = self.analyze_dump(dump_path)
        log_hits: list[dict[str, Any]] = []
        if log_path and os.path.exists(log_path):
            log_hits = self.parse_logs(log_path)
        procs = self.suspicious_processes(proclist or [])
        all_inds = [asdict(i) for i in inds]
        critical = sum(1 for i in all_inds if i["type"] in ("private_key", "aws_key"))
        summary = (
            f"{len(all_inds)} indicator(s), {len(log_hits)} log hit(s), "
            f"{len(procs)} suspicious process(es); {critical} high-value credential indicator(s)."
        )
        return TriageReport(
            dump_path=dump_path or "",
            log_path=log_path or "",
            indicators=all_inds,
            suspicious_processes=procs,
            log_hits=log_hits,
            summary=summary,
        )


def sample_proc_list() -> list[dict[str, str]]:
    return [
        {"pid": "1024", "name": "svchost.exe", "cmdline": "svchost.exe -k network", "user": "SYSTEM"},
        {"pid": "4321", "name": "powershell.exe", "cmdline": "powershell -enc U2FsdGVkX1...", "user": "admin"},
        {"pid": "5510", "name": "mimikatz.exe", "cmdline": "mimikatz.exe log passthes", "user": "admin"},
        {"pid": "7788", "name": "chrome.exe", "cmdline": "chrome.exe --headless", "user": "bob"},
    ]
