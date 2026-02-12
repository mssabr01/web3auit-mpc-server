"""Detector: Unchecked low-level calls in DeFi contexts.

Goes beyond Slither's generic low-level-calls detector by specifically
flagging ETH transfers and delegate calls inside DeFi-critical paths
(e.g. withdrawals, liquidations, reward distributions).
"""

from __future__ import annotations

import re
from pathlib import Path

from ..models import (
    AuditConfig,
    Confidence,
    Finding,
    Severity,
    SourceLocation,
    SourceTool,
)
from ._solidity_helpers import extract_functions, iter_solidity_files
from .registry import BaseDetector, get_registry

_LOW_LEVEL_CALL = re.compile(r"\.call\{[^}]*value\s*:", re.DOTALL)
_DELEGATECALL = re.compile(r"\.delegatecall\(")
_RETURN_CHECK = re.compile(r"\(\s*bool\s+(success|ok|sent)\s*[,)]")
_REQUIRE_CHECK = re.compile(r"require\s*\(\s*(success|ok|sent)\b")
_IF_CHECK = re.compile(r"if\s*\(\s*!(success|ok|sent)\b")

_DEFI_CONTEXT = re.compile(
    r"\b(withdraw|liquidat|claim|reward|harvest|distribute|payout|refund|settle)\b",
    re.IGNORECASE,
)


class UncheckedLowLevelDetector(BaseDetector):
    name = "unchecked-low-level"
    description = "Detects unchecked low-level ETH transfers and delegatecalls in DeFi-critical functions"
    tags = ["defi", "low-level"]

    async def detect(self, project_path: Path, config: AuditConfig) -> list[Finding]:
        findings: list[Finding] = []

        for sol_file in iter_solidity_files(project_path, config.exclude_paths):
            funcs = extract_functions(sol_file)
            rel = str(sol_file.relative_to(project_path))

            for fn in funcs:
                # Only flag functions in DeFi-critical paths
                in_defi_context = (
                    _DEFI_CONTEXT.search(fn.name)
                    or _DEFI_CONTEXT.search(fn.body)
                )

                # Check for .call{value:...} without return-value check
                if _LOW_LEVEL_CALL.search(fn.body):
                    has_return = _RETURN_CHECK.search(fn.body)
                    has_check = (
                        _REQUIRE_CHECK.search(fn.body)
                        or _IF_CHECK.search(fn.body)
                    )
                    if not has_return or not has_check:
                        sev = Severity.HIGH if in_defi_context else Severity.MEDIUM
                        findings.append(Finding(
                            title=f"Unchecked ETH transfer in `{fn.contract}.{fn.name}`",
                            detector="custom:unchecked-eth-transfer",
                            severity=sev,
                            confidence=Confidence.MEDIUM,
                            source_tool=SourceTool.CUSTOM,
                            description=(
                                f"`{fn.contract}.{fn.name}` uses `.call{{value: ...}}` "
                                f"without checking the boolean return value. "
                                f"Failed ETH transfers will silently succeed."
                            ),
                            locations=[SourceLocation(
                                file=rel, contract=fn.contract, function=fn.name,
                                line_start=fn.line_start, line_end=fn.line_end,
                            )],
                            recommendation=(
                                "Capture the return value: `(bool success, ) = addr.call{value: amt}(\"\");` "
                                "and `require(success, \"ETH transfer failed\");`"
                            ),
                            references=[
                                "https://swcregistry.io/docs/SWC-104",
                            ],
                        ))

                # Check for delegatecall
                if _DELEGATECALL.search(fn.body) and in_defi_context:
                    findings.append(Finding(
                        title=f"Delegatecall in DeFi-critical `{fn.contract}.{fn.name}`",
                        detector="custom:delegatecall-defi",
                        severity=Severity.HIGH,
                        confidence=Confidence.LOW,
                        source_tool=SourceTool.CUSTOM,
                        description=(
                            f"`{fn.contract}.{fn.name}` uses `delegatecall` inside a "
                            f"DeFi-sensitive function. The delegate target can overwrite "
                            f"storage or drain funds if not carefully restricted."
                        ),
                        locations=[SourceLocation(
                            file=rel, contract=fn.contract, function=fn.name,
                            line_start=fn.line_start, line_end=fn.line_end,
                        )],
                        recommendation=(
                            "Ensure the delegatecall target is immutable or behind an "
                            "access-controlled upgrade mechanism. Prefer direct calls "
                            "when possible."
                        ),
                        references=[
                            "https://swcregistry.io/docs/SWC-112",
                        ],
                    ))

        return findings


get_registry().register(UncheckedLowLevelDetector())
