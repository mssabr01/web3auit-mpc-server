"""Data models for PoC generation and validation."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class PoCArtifact(BaseModel):
    """A generated Proof-of-Concept test contract."""

    poc_id: str = ""
    finding_id: str
    finding_title: str
    detector: str
    strategy: str  # e.g. "reentrancy", "flash-loan"
    test_contract_name: str
    test_function_name: str
    test_file_path: str  # relative within the forge project
    solidity_code: str  # full .t.sol source
    solc_version: str = "0.8.24"
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: Literal["generated", "compiled", "passed", "failed", "error"] = (
        "generated"
    )
    notes: str = ""

    def model_post_init(self, _ctx: Any) -> None:
        if not self.poc_id:
            blob = f"{self.finding_id}|{self.strategy}"
            self.poc_id = hashlib.sha256(blob.encode()).hexdigest()[:12]


class ForgeCompileResult(BaseModel):
    """Outcome of ``forge build``."""

    success: bool
    stdout: str = ""
    stderr: str = ""
    compilation_time_ms: float = 0.0


class ForgeTestResult(BaseModel):
    """Result of a single Forge test function."""

    test_name: str
    passed: bool
    gas_used: int | None = None
    reason: str = ""  # revert / assertion message
    logs: list[str] = Field(default_factory=list)
    decoded_logs: list[str] = Field(default_factory=list)


class ForgeCoverageEntry(BaseModel):
    """Coverage stats for one source file."""

    file: str
    lines_hit: int = 0
    lines_total: int = 0
    branches_hit: int = 0
    branches_total: int = 0
    functions_hit: int = 0
    functions_total: int = 0

    @property
    def line_pct(self) -> float:
        return (self.lines_hit / self.lines_total * 100) if self.lines_total else 0.0


class PoEResult(BaseModel):
    """End-to-end Proof-of-Exploitability result."""

    finding_id: str
    finding_title: str
    poc: PoCArtifact
    compile_result: ForgeCompileResult | None = None
    test_results: list[ForgeTestResult] = Field(default_factory=list)
    proven_exploitable: bool = False
    overall_status: Literal["success", "compile_failed", "test_failed", "error"] = (
        "error"
    )
    error_message: str | None = None
    forge_project_path: str | None = None
