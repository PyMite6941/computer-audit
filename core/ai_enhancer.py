"""AI enhancement layer for computer-audit.

Design goals:
- Works OFFLINE by default (rule-based heuristics, no network, no API keys).
- Optional LLM backend via env vars: AI_API_BASE, AI_API_KEY, AI_MODEL.
  Any OpenAI-compatible endpoint works (local llama.cpp, Ollama, etc.).
- Graceful degradation: if the LLM is unavailable, fall back to rules.

Each algorithm domain can pass its findings through `enhance()` to get:
  - plain-language summary
  - risk explanation
  - remediation suggestions
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from typing import Any


class AIEnhancer(ABC):
    """Abstract enhancer. Subclass to plug in a different AI backend."""

    @abstractmethod
    def summarize(self, findings: list[dict[str, Any]], kind: str) -> str:
        ...

    @abstractmethod
    def explain(self, finding: dict[str, Any], kind: str) -> str:
        ...

    @abstractmethod
    def remediate(self, finding: dict[str, Any], kind: str) -> list[str]:
        ...


class RuleBasedEnhancer(AIEnhancer):
    """Deterministic, zero-dependency enhancer. Good enough for CI and air-gapped hosts."""

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def summarize(self, findings: list[dict[str, Any]], kind: str) -> str:
        if not findings:
            return f"No {kind} findings detected."
        counts: dict[str, int] = {}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1
        parts = [f"{counts.get(s, 0)} {s}" for s in self.SEVERITY_ORDER if counts.get(s)]
        top = sorted(findings, key=lambda f: self.SEVERITY_ORDER.get(str(f.get("severity", "info")).lower(), 9))[0]
        return (
            f"{kind}: {len(findings)} finding(s) - " + ", ".join(parts) + ". "
            f"Top concern: {top.get('title', top.get('id', 'unknown'))} ({top.get('severity', 'info')})."
        )

    def explain(self, finding: dict[str, Any], kind: str) -> str:
        title = finding.get("title", finding.get("id", "finding"))
        detail = finding.get("detail", "")
        return f"[{kind}] {title}: {detail}".strip()

    def remediate(self, finding: dict[str, Any], kind: str) -> list[str]:
        hints: dict[str, list[str]] = {
            "iam": [
                "Revoke or rotate the compromised credential immediately.",
                "Remove wildcard (*) actions from the role policy.",
                "Scope the role to the specific resources it needs (least privilege).",
                "Enable MFA and require re-authentication for privilege escalation.",
            ],
            "forensics": [
                "Isolate the affected host from the network.",
                "Preserve the memory dump and logs as evidence (hash them).",
                "Block identified IPs/domains at the firewall/proxy.",
                "Rotate credentials found in strings and re-image the host.",
            ],
            "api": [
                "Add authentication/authorization to the exposed endpoint.",
                "Implement object-level authorization checks (BOLA protection).",
                "Remove the endpoint or restrict it to internal networks.",
                "Rate-limit and monitor enumeration attempts.",
            ],
        }
        return hints.get(kind, ["Review the finding manually and apply least-privilege remediation."])


class LLMEnhancer(AIEnhancer):
    """Optional OpenAI-compatible LLM backend. Requires network + API key."""

    def __init__(self) -> None:
        self.base = os.environ.get("AI_API_BASE", "").rstrip("/")
        self.key = os.environ.get("AI_API_KEY", "")
        self.model = os.environ.get("AI_MODEL", "gpt-3.5-turbo")
        self._available = bool(self.base and self.key)

    def _chat(self, messages: list[dict[str, str]], timeout: int = 20) -> str:
        if not self._available:
            raise RuntimeError("LLM not configured (set AI_API_BASE and AI_API_KEY)")
        payload = json.dumps({"model": self.model, "messages": messages, "temperature": 0.2}).encode()
        req = urllib.request.Request(
            self.base.rstrip("/") + "/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]

    def summarize(self, findings: list[dict[str, Any]], kind: str) -> str:
        try:
            return self._chat(
                [
                    {"role": "system", "content": "You are a senior security engineer. Summarize findings concisely."},
                    {"role": "user", "content": f"Summarize these {kind} audit findings in 2-3 sentences: {json.dumps(findings)[:4000]}"},
                ]
            )
        except Exception as exc:  # noqa: BLE001 - degrade to rules
            return f"(LLM unavailable: {exc}) Falling back to rules: " + RuleBasedEnhancer().summarize(findings, kind)

    def explain(self, finding: dict[str, Any], kind: str) -> str:
        try:
            return self._chat(
                [
                    {"role": "system", "content": "Explain a single security finding to an on-call engineer."},
                    {"role": "user", "content": f"Explain this {kind} finding: {json.dumps(finding)}"},
                ]
            )
        except Exception as exc:  # noqa: BLE001
            return f"(LLM unavailable: {exc}) " + RuleBasedEnhancer().explain(finding, kind)

    def remediate(self, finding: dict[str, Any], kind: str) -> list[str]:
        try:
            text = self._chat(
                [
                    {"role": "system", "content": "Give 3 short, actionable remediation steps."},
                    {"role": "user", "content": f"Remediate this {kind} finding: {json.dumps(finding)}"},
                ]
            )
            return [line.strip("-• ").strip() for line in text.splitlines() if line.strip()][:3]
        except Exception as exc:  # noqa: BLE001
            return RuleBasedEnhancer().remediate(finding, kind)


def build_enhancer(force_llm: bool = False) -> AIEnhancer:
    """Factory: LLM if configured (and forced or available), else rules."""
    if force_llm or (os.environ.get("AI_API_BASE") and os.environ.get("AI_API_KEY")):
        return LLMEnhancer()
    return RuleBasedEnhancer()
