"""AI thinking module for computer-audit.

This is a SEPARATE module from `core/ai_enhancer.py`. The enhancer summarizes
findings after an audit runs. The AI thinker runs BEFORE/DURING an audit to
provide extra reasoning: it suggests what to look for, interprets ambiguous
findings, and recommends next steps. It is optional and offline-by-default.

Design goals:
- Offline rule-based thinker by default (no network, no API key).
- Optional LLM backend via env vars (same as enhancer).
- Never modifies system state — suggestions only.
- Runs in parallel with scanning via ThreadPoolExecutor.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ThinkingSuggestion:
    id: str
    category: str          # port | process | persistence | bloat | ai-bloat | network
    title: str
    detail: str
    confidence: str        # low | medium | high
    action: str            # what to do next
    os: str


@dataclass
class ThinkResult:
    os: str
    suggestions: list[dict[str, Any]]
    ai_summary: str | None


class AIThinker(ABC):
    """Abstract AI thinking backend."""

    @abstractmethod
    def think(self, context: dict[str, Any]) -> list[ThinkingSuggestion]:
        ...

    @abstractmethod
    def summarize(self, suggestions: list[dict[str, Any]]) -> str | None:
        ...


class RuleBasedThinker(AIThinker):
    """Offline rule-based thinker. Generates suggestions from scan context."""

    def think(self, context: dict[str, Any]) -> list[ThinkingSuggestion]:
        os_name = context.get("os", "unknown")
        suggestions: list[ThinkingSuggestion] = []

        # Port scanning suggestions
        open_ports = context.get("open_ports", 0)
        if open_ports:
            suggestions.append(ThinkingSuggestion(
                id="think-open-ports",
                category="network",
                title=f"Review {open_ports} open port(s)",
                detail=f"Open ports detected on localhost. Verify each is expected and not a backdoor.",
                confidence="high",
                action="Close unexpected ports or restrict via firewall.",
                os=os_name,
            ))

        # Process suggestions
        suspicious = context.get("suspicious_processes", 0)
        if suspicious > 0:
            suggestions.append(ThinkingSuggestion(
                id="think-suspicious-procs",
                category="process",
                title=f"Investigate {suspicious} suspicious process(es)",
                detail="Processes matched known malware/loader keywords. "
                       "Check parent PID, command line, and network connections.",
                confidence="high",
                action="Kill or isolate the host if confirmed malicious.",
                os=os_name,
            ))

        # Persistence suggestions
        persistence = context.get("persistence_items", 0)
        if persistence > 0:
            suggestions.append(ThinkingSuggestion(
                id="think-persistence",
                category="persistence",
                title=f"Review {persistence} persistence mechanism(s)",
                detail="Startup keys, crontabs, or systemd timers found. "
                       "Verify each is legitimate software, not malware persistence.",
                confidence="medium",
                action="Disable unauthorized persistence and monitor for re-creation.",
                os=os_name,
            ))

        # AI bloat suggestions
        ai_bloat = context.get("ai_bloat_count", 0)
        if ai_bloat > 0:
            suggestions.append(ThinkingSuggestion(
                id="think-ai-bloat",
                category="ai-bloat",
                title=f"Disable {ai_bloat} AI-bloat item(s)",
                detail="AI-related features (Copilot, Recall, local LLM agents) detected. "
                       "These consume resources and may collect telemetry.",
                confidence="medium",
                action="Run `audit removal --apply` to disable after review.",
                os=os_name,
            ))

        # Network connection suggestions
        net_conns = context.get("network_connections", 0)
        if net_conns > 20:
            suggestions.append(ThinkingSuggestion(
                id="think-high-network",
                category="network",
                title=f"High network activity: {net_conns} connection(s)",
                detail="Many active network connections. Check for data exfiltration "
                       "or command-and-control beacons.",
                confidence="medium",
                action="Inspect destination IPs and block unknown ones.",
                os=os_name,
            ))

        if not suggestions:
            suggestions.append(ThinkingSuggestion(
                id="think-clean",
                category="general",
                title="No immediate concerns detected",
                detail="Scan results are within normal parameters. "
                       "Continue regular monitoring.",
                confidence="low",
                action="Schedule periodic re-scans.",
                os=os_name,
            ))

        return suggestions

    def summarize(self, suggestions: list[dict[str, Any]]) -> str | None:
        if not suggestions:
            return None
        high = sum(1 for s in suggestions if s.get("confidence") == "high")
        med = sum(1 for s in suggestions if s.get("confidence") == "medium")
        parts = []
        if high:
            parts.append(f"{high} high-confidence")
        if med:
            parts.append(f"{med} medium-confidence")
        return ("AI thinker: " + ", ".join(parts) + " suggestion(s). "
                "Review each before acting.") if parts else None


class LLMThinker(AIThinker):
    """Optional OpenAI-compatible LLM thinker. Requires network + API key."""

    def __init__(self) -> None:
        self.base = os.environ.get("AI_API_BASE", "").rstrip("/")
        self.key = os.environ.get("AI_API_KEY", "")
        self.model = os.environ.get("AI_MODEL", "gpt-3.5-turbo")
        self._available = bool(self.base and self.key)

    def _chat(self, messages: list[dict[str, str]], timeout: int = 20) -> str:
        if not self._available:
            raise RuntimeError("LLM thinker not configured (set AI_API_BASE and AI_API_KEY)")
        payload = json.dumps({"model": self.model, "messages": messages, "temperature": 0.3}).encode()
        req = urllib.request.Request(
            self.base.rstrip("/") + "/chat/completions",
            data=payload,
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.key}"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        return data["choices"][0]["message"]["content"]

    def think(self, context: dict[str, Any]) -> list[ThinkingSuggestion]:
        try:
            text = self._chat([
                {"role": "system", "content": "You are a senior security analyst. Given audit context, suggest what to investigate next. Return a JSON list of {category, title, detail, confidence, action}."},
                {"role": "user", "content": f"Context: {json.dumps(context)[:6000]}"},
            ])
            # Parse best-effort; fall back to rules on failure
            try:
                data = json.loads(text)
                out: list[ThinkingSuggestion] = []
                for item in data:
                    out.append(ThinkingSuggestion(
                        id=f"think-llm-{abs(hash(item.get('title', ''))) % 100000}",
                        category=item.get("category", "general"),
                        title=item.get("title", "AI suggestion"),
                        detail=item.get("detail", ""),
                        confidence=item.get("confidence", "medium"),
                        action=item.get("action", "Review manually"),
                        os=context.get("os", "unknown"),
                    ))
                return out
            except (json.JSONDecodeError, KeyError, TypeError):
                return RuleBasedThinker().think(context)
        except Exception as exc:  # noqa: BLE001 - degrade to rules
            return RuleBasedThinker().think(context)

    def summarize(self, suggestions: list[dict[str, Any]]) -> str | None:
        try:
            text = self._chat([
                {"role": "system", "content": "Summarize security suggestions in one sentence."},
                {"role": "user", "content": json.dumps(suggestions)[:4000]},
            ])
            return text.strip()
        except Exception:  # noqa: BLE001
            return RuleBasedThinker().summarize(suggestions)


def build_thinker(force_llm: bool = False) -> AIThinker:
    if force_llm or (os.environ.get("AI_API_BASE") and os.environ.get("AI_API_KEY")):
        return LLMThinker()
    return RuleBasedThinker()
