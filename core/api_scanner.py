"""API Security & Microservice Scanner.

Dynamically discovers endpoints from a target, tests for common authorization
flaws (broken object-level authorization via ID enumeration, missing auth),
and maps API dependencies. Output is JSON + optional text report.

Stdlib-only network access so it runs on any OS without extra installs.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

PATH_RE = re.compile(r'["\'](/[A-Za-z0-9_./{}-]+)["\']')
ID_RE = re.compile(r"/(\d{1,6})([/?]|$)")

SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    endpoint: str
    method: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


class APIScanner:
    """Lightweight dynamic API security scanner."""

    def __init__(self, timeout: int = 8, user_agent: str = "computer-audit-scanner/1.0") -> None:
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent, "Accept": "application/json, text/html, */*"}
        self.discovered: list[str] = []
        self.findings: list[Finding] = []

    # ----------------------------------------------------------- discovery
    def fetch(self, url: str) -> tuple[int, str, dict[str, str]]:
        req = urllib.request.Request(url, headers=self.headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as err:
            try:
                body = err.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return err.code, body, dict(err.headers)
        except Exception as exc:  # noqa: BLE001 - network unreachable is a valid result
            return 0, "", {}

    def discover_endpoints(self, base_url: str) -> list[str]:
        found: set[str] = set()
        parsed = urllib.parse.urlparse(base_url)
        root = f"{parsed.scheme}://{parsed.netloc}"

        for path in ("/robots.txt", "/sitemap.xml", "/api", "/openapi.json", "/swagger.json", "/docs"):
            status, body, _ = self.fetch(root + path)
            if status == 200 and body:
                for m in PATH_RE.finditer(body):
                    found.add(m.group(1))

        # Crawl homepage + common API routes for links
        for url in (base_url, root + "/api", root + "/v1", root + "/graphql"):
            status, body, _ = self.fetch(url)
            if status == 200 and body:
                for m in PATH_RE.finditer(body):
                    found.add(m.group(1))

        self.discovered = sorted(found)
        return self.discovered

    # ------------------------------------------------------------- scanning
    def _try(self, endpoint: str, method: str = "GET") -> tuple[int, str, dict[str, str]]:
        parsed = urllib.parse.urlparse(endpoint)
        full = endpoint if parsed.scheme else self.discovered[0] + endpoint if self.discovered else endpoint
        return self.fetch(full)

    def scan_bola(self, endpoint: str) -> list[Finding]:
        """BOLA probe: swap numeric IDs and compare responses."""
        out: list[Finding] = []
        m = ID_RE.search(endpoint)
        if not m:
            return out
        original_id = m.group(1)
        prefix, suffix = endpoint[: m.start(1)], endpoint[m.end(1):]
        for probe in ("1", "2", "999999", "0"):
            if probe == original_id:
                continue
            probe_url = prefix + probe + suffix
            status, body, _ = self.fetch(probe_url)
            if status == 200 and body:
                out.append(
                    Finding(
                        id="api-bola",
                        title="Possible BOLA - ID substitution returned data",
                        severity="high",
                        endpoint=probe_url,
                        method="GET",
                        detail=f"Replacing ID {original_id} with {probe} returned HTTP 200 with data.",
                        evidence={"original_id": original_id, "probe_id": probe, "status": status, "body_len": len(body)},
                    )
                )
                break
        return out

    def scan_auth(self, endpoint: str) -> list[Finding]:
        """Detect unauthenticated endpoints that return data."""
        out: list[Finding] = []
        status, body, headers = self.fetch(endpoint)
        if status == 200 and body and len(body) > 20:
            auth_hdr = headers.get("www-authenticate") or headers.get("WWW-Authenticate", "")
            if not auth_hdr:
                out.append(
                    Finding(
                        id="api-missing-auth",
                        title="Unauthenticated endpoint returns data",
                        severity="medium",
                        endpoint=endpoint,
                        method="GET",
                        detail="Endpoint returned data without any authentication challenge.",
                        evidence={"status": status, "body_len": len(body), "auth_header": auth_hdr},
                    )
                )
        return out

    def scan(self, target: str) -> dict[str, Any]:
        self.discovered = self.discover_endpoints(target)
        self.findings = []
        for ep in self.discovered:
            full = ep if ep.startswith("http") else urllib.parse.urljoin(target, ep)
            self.findings.extend(self.scan_auth(full))
            self.findings.extend(self.scan_bola(full))
        return {
            "target": target,
            "endpoints_discovered": len(self.discovered),
            "endpoints": self.discovered,
            "findings": [asdict(f) for f in self.findings],
        }


def sample_target() -> str:
    return "http://127.0.0.1:8000"
