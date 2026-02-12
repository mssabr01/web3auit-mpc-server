"""Detector: Flash-loan vulnerability patterns.

Flags functions that:
  1. Accept a callback / implement known flash-loan receiver interfaces
  2. Perform state changes (storage writes, token transfers) inside a
     flash-loan callback without re-entrancy protection
  3. Use unchecked balances as decision inputs after an external call
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
from ._solidity_helpers import SolFunction, extract_functions, iter_solidity_files
from .registry import BaseDetector, get_registry

# Known flash-loan callback signatures (EIP-3156, Aave, dYdX, Uniswap v3)
_FLASH_CALLBACKS = re.compile(
    r"(onFlashLoan|executeOperation|callFunction|uniswapV3FlashCallback"
    r"|pancakeV3FlashCallback|receiveFlashLoan)",
    re.IGNORECASE,
)

# Patterns indicating token movement or state change
_STATE_CHANGE = re.compile(
    r"\b(transfer|transferFrom|safeTransfer|safeTransferFrom|approve|mint|burn"
    r"|swap|deposit|withdraw|\.call\{value:)\b"
)

_BALANCE_CHECK = re.compile(r"\b(balanceOf|getReserves|totalSupply)\b")

# Common guard modifiers/patterns
_GUARDS = re.compile(r"\b(nonReentrant|ReentrancyGuard|_nonReentrantBefore|lock)\b", re.IGNORECASE)


class FlashLoanDetector(BaseDetector):
    name = "flash-loan"
    description = "Detects flash-loan attack patterns: unguarded callbacks and balance-dependent logic"
    tags = ["defi", "flash-loan"]

    async def detect(self, project_path: Path, config: AuditConfig) -> list[Finding]:
        findings: list[Finding] = []

        for sol_file in iter_solidity_files(project_path, config.exclude_paths):
            funcs = extract_functions(sol_file)
            for fn in funcs:
                findings.extend(self._check_function(fn, sol_file, project_path))

        return findings

    def _check_function(
        self, fn: SolFunction, sol_file: Path, root: Path
    ) -> list[Finding]:
        results: list[Finding] = []
        rel = str(sol_file.relative_to(root))

        # --- Pattern 1: Flash-loan callback without reentrancy guard --------
        if _FLASH_CALLBACKS.search(fn.name):
            has_guard = _GUARDS.search(fn.body) or any(
                _GUARDS.search(m) for m in fn.modifiers
            )
            has_state_change = _STATE_CHANGE.search(fn.body)

            if has_state_change and not has_guard:
                results.append(Finding(
                    title=f"Unguarded flash-loan callback `{fn.name}` in {fn.contract}",
                    detector="custom:flash-loan-unguarded-callback",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    source_tool=SourceTool.CUSTOM,
                    description=(
                        f"`{fn.contract}.{fn.name}` implements a flash-loan callback and "
                        f"performs state-changing operations without a reentrancy guard. "
                        f"An attacker could re-enter during the flash loan to manipulate state."
                    ),
                    locations=[SourceLocation(
                        file=rel, contract=fn.contract,
                        function=fn.name, line_start=fn.line_start, line_end=fn.line_end,
                    )],
                    recommendation=(
                        "Add a `nonReentrant` modifier or equivalent mutex to the callback. "
                        "Ensure all state changes happen before external calls."
                    ),
                    references=[
                        "https://eips.ethereum.org/EIPS/eip-3156",
                        "https://swcregistry.io/docs/SWC-107",
                    ],
                ))

        # --- Pattern 2: Balance-based decisions after external call ----------
        if _BALANCE_CHECK.search(fn.body) and _STATE_CHANGE.search(fn.body):
            # Rough heuristic: balanceOf appears AFTER a .call or transfer
            call_pos = None
            for m in re.finditer(r"\.(call|transfer|send)\b", fn.body):
                call_pos = m.start()
                break
            if call_pos is not None:
                for m in _BALANCE_CHECK.finditer(fn.body):
                    if m.start() > call_pos:
                        results.append(Finding(
                            title=f"Balance read after external call in `{fn.contract}.{fn.name}`",
                            detector="custom:flash-loan-balance-after-call",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            source_tool=SourceTool.CUSTOM,
                            description=(
                                f"`{fn.contract}.{fn.name}` reads a token balance after making "
                                f"an external call. In a flash-loan context this balance can be "
                                f"temporarily inflated, leading to incorrect logic."
                            ),
                            locations=[SourceLocation(
                                file=rel, contract=fn.contract,
                                function=fn.name, line_start=fn.line_start, line_end=fn.line_end,
                            )],
                            recommendation=(
                                "Cache balances before external calls and compare. "
                                "Consider using checks-effects-interactions pattern."
                            ),
                            references=[
                                "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
                            ],
                        ))
                        break  # one finding per function

        return results


# Auto-register
get_registry().register(FlashLoanDetector())
