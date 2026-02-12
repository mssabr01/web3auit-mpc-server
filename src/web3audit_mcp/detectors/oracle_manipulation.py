"""Detector: Oracle manipulation vulnerabilities.

Flags:
  1. Spot-price usage from AMM reserves (getReserves) without TWAP
  2. Single-source oracle dependency (no fallback)
  3. Missing staleness checks on Chainlink feeds (latestRoundData without
     updatedAt validation)
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

# Patterns
_SPOT_PRICE = re.compile(r"\b(getReserves|reserve0|reserve1|slot0)\b")
_TWAP = re.compile(r"\b(observe|consult|TWAP|twap|cumulativePrice|tickCumulatives)\b", re.IGNORECASE)

_CHAINLINK_CALL = re.compile(r"\blatestRoundData\b")
_STALENESS_CHECK = re.compile(r"\bupdatedAt\b")
_ROUND_COMPLETENESS = re.compile(r"\bansweredInRound\b")

_ORACLE_INTERFACE = re.compile(
    r"\b(AggregatorV3Interface|IPriceFeed|IOracle|PriceOracle|getPrice|getUnderlyingPrice)\b"
)
_FALLBACK_PATTERN = re.compile(r"\b(fallback[Oo]racle|secondary[Oo]racle|backup|try\s*\{)\b")


class OracleManipulationDetector(BaseDetector):
    name = "oracle-manipulation"
    description = "Detects oracle manipulation risks: spot-price reliance, stale Chainlink feeds, single-source oracles"
    tags = ["defi", "oracle"]

    async def detect(self, project_path: Path, config: AuditConfig) -> list[Finding]:
        findings: list[Finding] = []

        for sol_file in iter_solidity_files(project_path, config.exclude_paths):
            funcs = extract_functions(sol_file)
            rel = str(sol_file.relative_to(project_path))
            source = sol_file.read_text(errors="replace")

            for fn in funcs:
                # --- 1. Spot-price from AMM reserves without TWAP -----------
                if _SPOT_PRICE.search(fn.body) and not _TWAP.search(fn.body):
                    findings.append(Finding(
                        title=f"Spot-price oracle in `{fn.contract}.{fn.name}`",
                        detector="custom:oracle-spot-price",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        source_tool=SourceTool.CUSTOM,
                        description=(
                            f"`{fn.contract}.{fn.name}` reads AMM reserves or slot0 "
                            f"to derive a price without using a TWAP. Spot prices are "
                            f"trivially manipulable via flash loans."
                        ),
                        locations=[SourceLocation(
                            file=rel, contract=fn.contract, function=fn.name,
                            line_start=fn.line_start, line_end=fn.line_end,
                        )],
                        recommendation=(
                            "Use a TWAP oracle (e.g. Uniswap v3 `observe()`) or "
                            "Chainlink price feeds instead of spot reserves."
                        ),
                        references=[
                            "https://shouldiusespotpriceasmyoracle.com/",
                            "https://docs.chain.link/data-feeds",
                        ],
                    ))

                # --- 2. Chainlink without staleness check -------------------
                if _CHAINLINK_CALL.search(fn.body):
                    has_staleness = _STALENESS_CHECK.search(fn.body)
                    has_round_check = _ROUND_COMPLETENESS.search(fn.body)
                    if not has_staleness:
                        findings.append(Finding(
                            title=f"Stale Chainlink feed in `{fn.contract}.{fn.name}`",
                            detector="custom:oracle-chainlink-stale",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            source_tool=SourceTool.CUSTOM,
                            description=(
                                f"`{fn.contract}.{fn.name}` calls `latestRoundData()` "
                                f"without validating `updatedAt` against a heartbeat. "
                                f"Stale prices can cause liquidations or arbitrage."
                            ),
                            locations=[SourceLocation(
                                file=rel, contract=fn.contract, function=fn.name,
                                line_start=fn.line_start, line_end=fn.line_end,
                            )],
                            recommendation=(
                                "Check `updatedAt` is within the feed's heartbeat interval. "
                                "Also validate `answeredInRound >= roundId` for round completeness."
                            ),
                            references=[
                                "https://docs.chain.link/data-feeds/using-data-feeds#check-the-timestamp-of-the-latest-answer",
                            ],
                        ))

            # --- 3. Single-source oracle (file-level check) -----------------
            if _ORACLE_INTERFACE.search(source) and not _FALLBACK_PATTERN.search(source):
                findings.append(Finding(
                    title=f"Single-source oracle in `{rel}`",
                    detector="custom:oracle-single-source",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    source_tool=SourceTool.CUSTOM,
                    description=(
                        f"`{rel}` depends on an oracle interface but has no visible "
                        f"fallback mechanism. If the primary oracle goes down or is "
                        f"manipulated, the contract has no secondary source."
                    ),
                    locations=[SourceLocation(file=rel)],
                    recommendation=(
                        "Implement a fallback oracle (e.g. Chainlink + TWAP) with "
                        "automatic failover via try/catch."
                    ),
                    references=[],
                ))

        return findings


get_registry().register(OracleManipulationDetector())
