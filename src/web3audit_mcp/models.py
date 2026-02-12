"""Canonical data models shared across runners, detectors, dedup, and reports."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFORMATIONAL: 4,
        }[self]


class Confidence(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"

    @property
    def rank(self) -> int:
        return {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}[self]


class SourceTool(str, Enum):
    SLITHER = "slither"
    ADERYN = "aderyn"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

class SourceLocation(BaseModel):
    """A precise location inside a Solidity file."""

    file: str
    contract: str | None = None
    function: str | None = None
    line_start: int | None = None
    line_end: int | None = None

    @property
    def key(self) -> str:
        """Normalised location string used for dedup hashing."""
        parts = [self.file]
        if self.contract:
            parts.append(self.contract)
        if self.function:
            parts.append(self.function)
        if self.line_start is not None:
            parts.append(str(self.line_start))
        return ":".join(parts)


class Finding(BaseModel):
    """Single audit finding — the universal currency of this server."""

    id: str = ""
    title: str
    detector: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    source_tool: SourceTool
    description: str = ""
    locations: list[SourceLocation] = Field(default_factory=list)
    recommendation: str = ""
    references: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)

    def model_post_init(self, _context: Any) -> None:
        if not self.id:
            self.id = self._compute_id()

    def _compute_id(self) -> str:
        blob = f"{self.detector}|{self.severity.value}"
        for loc in sorted(self.locations, key=lambda l: l.key):
            blob += f"|{loc.key}"
        return hashlib.sha256(blob.encode()).hexdigest()[:12]


class AuditConfig(BaseModel):
    """Runtime configuration for a single audit run."""

    project_path: str = "/contracts"
    run_slither: bool = True
    run_aderyn: bool = True
    run_custom: bool = True
    custom_detectors: list[str] | None = None  # None = all
    slither_timeout: int = 300
    aderyn_timeout: int = 300
    solc_version: str | None = None
    exclude_paths: list[str] = Field(default_factory=list)
    extra_slither_args: list[str] = Field(default_factory=list)
    extra_aderyn_args: list[str] = Field(default_factory=list)


class AuditResult(BaseModel):
    """Aggregated result of a full audit run."""

    project_path: str
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    findings: list[Finding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    tools_ran: list[str] = Field(default_factory=list)
    dedup_removed: int = 0

    # --- convenience helpers ------------------------------------------------

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        groups: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            groups[f.severity].append(f)
        return groups

    @property
    def summary_counts(self) -> dict[str, int]:
        return {s.value: len(fs) for s, fs in self.by_severity.items()}
