"""Detector: Price / slippage manipulation patterns.

Flags:
  1. Swaps with hardcoded zero slippage (amountOutMin = 0)
  2. Missing deadline parameters on DEX swaps
  3. Token approval to max uint without revocation patterns
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

_SWAP_CALLS = re.compile(
    r"\b(swapExactTokensForTokens|swapTokensForExactTokens|exactInputSingle"
    r"|exactInput|exactOutputSingle|exactOutput|swap)\b"
)
_ZERO_SLIPPAGE = re.compile(
    r"(amountOutMin\s*[:=]\s*0|,\s*0\s*,\s*address|minAmountOut\s*[:=]\s*0)"
)
_DEADLINE = re.compile(r"\b(deadline|block\.timestamp\s*\+)\b")
_MAX_APPROVE = re.compile(
    r"\.approve\s*\([^)]*(?:type\(uint256\)\.max|uint256\(-1\)|0xfff+|2\*\*256\s*-\s*1)"
)


class PriceManipulationDetector(BaseDetector):
    name = "price-manipulation"
    description = "Detects slippage / deadline / approval issues in DEX interactions"
    tags = ["defi", "dex", "slippage"]

    async def detect(self, project_path: Path, config: AuditConfig) -> list[Finding]:
        findings: list[Finding] = []

        for sol_file in iter_solidity_files(project_path, config.exclude_paths):
            funcs = extract_functions(sol_file)
            rel = str(sol_file.relative_to(project_path))

            for fn in funcs:
                # 1. Zero slippage on swaps
                if _SWAP_CALLS.search(fn.body) and _ZERO_SLIPPAGE.search(fn.body):
                    findings.append(Finding(
                        title=f"Zero slippage tolerance in `{fn.contract}.{fn.name}`",
                        detector="custom:price-zero-slippage",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        source_tool=SourceTool.CUSTOM,
                        description=(
                            f"`{fn.contract}.{fn.name}` calls a swap function with "
                            f"`amountOutMin = 0`, accepting any output amount. "
                            f"This makes the transaction vulnerable to sandwich attacks."
                        ),
                        locations=[SourceLocation(
                            file=rel, contract=fn.contract, function=fn.name,
                            line_start=fn.line_start, line_end=fn.line_end,
                        )],
                        recommendation=(
                            "Calculate a minimum output based on the expected price "
                            "minus an acceptable slippage percentage. Consider using an "
                            "oracle to determine fair price."
                        ),
                        references=[
                            "https://swcregistry.io/docs/SWC-116",
                        ],
                    ))

                # 2. Missing deadline on swap
                if _SWAP_CALLS.search(fn.body) and not _DEADLINE.search(fn.body):
                    findings.append(Finding(
                        title=f"Missing swap deadline in `{fn.contract}.{fn.name}`",
                        detector="custom:price-no-deadline",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        source_tool=SourceTool.CUSTOM,
                        description=(
                            f"`{fn.contract}.{fn.name}` performs a swap without setting "
                            f"a deadline. Miners can hold the transaction and execute it "
                            f"at a less favourable price later."
                        ),
                        locations=[SourceLocation(
                            file=rel, contract=fn.contract, function=fn.name,
                            line_start=fn.line_start, line_end=fn.line_end,
                        )],
                        recommendation=(
                            "Pass `block.timestamp + DEADLINE_BUFFER` as the deadline "
                            "parameter, or accept it as a function argument from the caller."
                        ),
                        references=[],
                    ))

                # 3. Max approval
                if _MAX_APPROVE.search(fn.body):
                    findings.append(Finding(
                        title=f"Max token approval in `{fn.contract}.{fn.name}`",
                        detector="custom:price-max-approval",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        source_tool=SourceTool.CUSTOM,
                        description=(
                            f"`{fn.contract}.{fn.name}` approves `type(uint256).max` "
                            f"tokens to a spender. If the spender contract is compromised "
                            f"or malicious, all user tokens are at risk."
                        ),
                        locations=[SourceLocation(
                            file=rel, contract=fn.contract, function=fn.name,
                            line_start=fn.line_start, line_end=fn.line_end,
                        )],
                        recommendation=(
                            "Approve only the amount needed for the current operation, "
                            "or implement an approval-reset pattern."
                        ),
                        references=[],
                    ))

        return findings


get_registry().register(PriceManipulationDetector())
