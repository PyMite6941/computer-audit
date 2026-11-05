"""Open port scanner for computer-audit.

Scans common ports on localhost and (optionally) remote hosts using parallel
threading via ThreadPoolExecutor. Results feed into the threat scanner and AI
thinker so open ports are treated as first-class audit findings.

Stdlib-only — works on Windows, macOS, and Linux without extra installs.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from typing import Any


# Common ports worth checking on a host
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 993, 995, 1433, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 27017,
]


@dataclass
class PortResult:
    port: int
    open: bool
    service: str | None = None


@dataclass
class PortScanReport:
    target: str
    open_ports: list[int]
    scanned_ports: int
    summary: str


def _probe_port(target: str, port: int, timeout: float = 1.0) -> PortResult:
    """Attempt a TCP connect to a single port."""
    try:
        with socket.create_connection((target, port), timeout=timeout):
            return PortResult(port=port, open=True, service=_guess_service(port))
    except (OSError, socket.timeout, ConnectionRefusedError):
        return PortResult(port=port, open=False)


def _guess_service(port: int) -> str | None:
    services = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap",
        443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
        1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
        5900: "vnc", 6379: "redis", 8080: "http-alt", 8443: "https-alt",
        27017: "mongodb",
    }
    return services.get(port)


def scan_ports(target: str = "127.0.0.1", ports: list[int] | None = None,
               workers: int = 50, timeout: float = 1.0) -> PortScanReport:
    """Scan ports on target in parallel using ThreadPoolExecutor."""
    port_list = ports or COMMON_PORTS
    open_ports: list[int] = []
    scanned = 0

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_probe_port, target, p, timeout): p for p in port_list}
        for future in as_completed(futures):
            scanned += 1
            result = future.result()
            if result.open:
                open_ports.append(result.port)

    open_ports.sort()
    summary = (
        f"Scanned {scanned} port(s) on {target}: "
        f"{len(open_ports)} open ({', '.join(str(p) for p in open_ports) or 'none'})."
    )
    return PortScanReport(
        target=target,
        open_ports=open_ports,
        scanned_ports=scanned,
        summary=summary,
    )
