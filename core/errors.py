"""Minecraft-style error handling for computer-audit.

Errors follow Minecraft's format: a crash screen with an error code,
human-readable description, keyword(s) for searching, and a documentation
reference. This makes failures clear and actionable instead of opaque tracebacks.

Usage:
    from core.errors import AuditError, error_panel
    raise AuditError("PORT_SCAN_FAILED", "Could not bind to interface", keywords=["port", "bind", "firewall"])

The CLI catches AuditError and prints a formatted panel before exiting cleanly.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AuditError(Exception):
    """Structured audit error with Minecraft-style documentation."""

    code: str          # e.g. "PORT_SCAN_FAILED", "AI_BACKEND_UNREACHABLE"
    message: str       # human-readable description
    keywords: list[str] = field(default_factory=list)  # search keywords
    docs: str = ""     # documentation reference URL or path
    detail: dict[str, Any] = field(default_factory=dict)  # extra context
    exit_code: int = 1

    def __str__(self) -> str:
        return self.message

    def panel(self) -> str:
        """Render a Minecraft-style crash/error panel."""
        lines: list[str] = []
        lines.append("==================== computer-audit ERROR ====================")
        lines.append(f"  Code: {self.code}")
        lines.append(f"  Message: {self.message}")
        if self.keywords:
            kw = ", ".join(self.keywords)
            lines.append(f"  Keywords: {kw}")
        if self.docs:
            lines.append(f"  Docs: {self.docs}")
        if self.detail:
            lines.append("  Details:")
            for k, v in self.detail.items():
                lines.append(f"    {k}: {v}")
        lines.append("--------------------------------------------------------------")
        lines.append("  Search these keywords in the documentation or issue tracker.")
        lines.append("  If the issue persists, open a bug report with the error code.")
        lines.append("================================================================")
        return "\n".join(lines)

    def display(self) -> None:
        print(self.panel(), file=sys.stderr)


def handle_error(err: Exception) -> int:
    """Central error handler. AuditError renders a panel; others render a generic one."""
    if isinstance(err, AuditError):
        err.display()
        return err.exit_code
    # Generic fallback for unexpected exceptions
    generic = AuditError(
        code="UNEXPECTED_ERROR",
        message=str(err) or "An unexpected error occurred",
        keywords=["error", "exception", "crash"],
        docs="docs/troubleshooting.md",
        detail={"type": type(err).__name__},
        exit_code=1,
    )
    generic.display()
    return 1
