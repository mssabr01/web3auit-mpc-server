"""Forge build / test / coverage runner."""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path

from ..models import AuditConfig
from ..runners.base import BaseRunner
from ..poc.models import ForgeCompileResult, ForgeCoverageEntry, ForgeTestResult

logger = logging.getLogger(__name__)


class ForgeRunner(BaseRunner):
    """Execute ``forge`` commands and parse structured output."""

    name = "forge"

    # BaseRunner.run() is abstract but we don't use the audit-finding flow;
    # provide a no-op so the class is concrete.
    async def run(self, config: AuditConfig) -> list:
        return []

    # ------------------------------------------------------------------
    # Compile
    # ------------------------------------------------------------------

    async def compile(
        self,
        project_path: Path,
        solc_version: str | None = None,
        timeout: int = 120,
    ) -> ForgeCompileResult:
        """``forge build`` and return structured result."""
        cmd = ["forge", "build"]
        if solc_version:
            cmd += ["--use", solc_version]

        t0 = time.monotonic()
        try:
            stdout, stderr, rc = await self._exec(
                cmd, cwd=project_path, timeout=timeout,
            )
        except TimeoutError:
            return ForgeCompileResult(
                success=False,
                stderr=f"forge build timed out after {timeout}s",
            )

        elapsed = (time.monotonic() - t0) * 1000
        return ForgeCompileResult(
            success=(rc == 0),
            stdout=stdout,
            stderr=stderr,
            compilation_time_ms=elapsed,
        )

    # ------------------------------------------------------------------
    # Test
    # ------------------------------------------------------------------

    async def test(
        self,
        project_path: Path,
        test_filter: str | None = None,
        verbosity: int = 2,
        fork_url: str | None = None,
        fork_block: int | None = None,
        ffi: bool = False,
        timeout: int = 300,
    ) -> list[ForgeTestResult]:
        """``forge test --json`` and parse per-test results."""
        cmd = ["forge", "test", "--json"]
        cmd.append(f"-{'v' * min(verbosity, 5)}")

        if test_filter:
            cmd += ["--match-test", test_filter]
        if fork_url:
            cmd += ["--fork-url", fork_url]
        if fork_block is not None:
            cmd += ["--fork-block-number", str(fork_block)]
        if ffi:
            cmd.append("--ffi")

        try:
            stdout, stderr, rc = await self._exec(
                cmd, cwd=project_path, timeout=timeout,
            )
        except TimeoutError:
            return [ForgeTestResult(
                test_name="<timeout>",
                passed=False,
                reason=f"forge test timed out after {timeout}s",
            )]

        return self._parse_test_json(stdout, stderr)

    # ------------------------------------------------------------------
    # Coverage
    # ------------------------------------------------------------------

    async def coverage(
        self,
        project_path: Path,
        timeout: int = 300,
    ) -> list[ForgeCoverageEntry]:
        """``forge coverage`` and parse the summary table."""
        cmd = ["forge", "coverage"]
        try:
            stdout, stderr, rc = await self._exec(
                cmd, cwd=project_path, timeout=timeout,
            )
        except TimeoutError:
            logger.warning("forge coverage timed out")
            return []

        if rc != 0:
            logger.error("forge coverage failed: %s", stderr[:500])
            return []

        return self._parse_coverage(stdout)

    # ------------------------------------------------------------------
    # Gas report
    # ------------------------------------------------------------------

    async def gas_report(
        self,
        project_path: Path,
        test_filter: str | None = None,
        timeout: int = 300,
    ) -> str:
        """``forge test --gas-report`` and return raw output."""
        cmd = ["forge", "test", "--gas-report"]
        if test_filter:
            cmd += ["--match-test", test_filter]
        try:
            stdout, _stderr, _rc = await self._exec(
                cmd, cwd=project_path, timeout=timeout,
            )
        except TimeoutError:
            return "gas report timed out"
        return stdout

    # ------------------------------------------------------------------
    # Parsers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_test_json(stdout: str, stderr: str) -> list[ForgeTestResult]:
        """Parse ``forge test --json`` output.

        Forge emits one JSON object per test-suite file. Each object maps
        test names to result dicts.
        """
        results: list[ForgeTestResult] = []

        # forge may output multiple JSON objects (one per suite) separated
        # by newlines, or a single top-level object.
        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Walk the nested structure
            for suite_path, suite_data in data.items():
                test_results = suite_data
                # Sometimes wrapped: {"test_results": {...}}
                if isinstance(suite_data, dict) and "test_results" in suite_data:
                    test_results = suite_data["test_results"]
                if not isinstance(test_results, dict):
                    continue

                for test_name, info in test_results.items():
                    if not isinstance(info, dict):
                        continue
                    status = info.get("status", info.get("success", ""))
                    passed = status == "Success" or status is True
                    gas = info.get("gas_used") or info.get("gas")

                    decoded = info.get("decoded_logs", [])
                    logs = info.get("logs", [])
                    reason = info.get("reason", "")

                    results.append(ForgeTestResult(
                        test_name=f"{suite_path}::{test_name}",
                        passed=passed,
                        gas_used=int(gas) if gas else None,
                        reason=reason or "",
                        logs=logs if isinstance(logs, list) else [],
                        decoded_logs=decoded if isinstance(decoded, list) else [],
                    ))

        # If JSON parsing yielded nothing, try to extract from stderr
        if not results and stderr:
            # Look for "FAIL" / "PASS" lines
            for m in re.finditer(
                r"(PASS|FAIL)\s+(\S+)\s+\(gas:\s*(\d+)\)", stderr + stdout
            ):
                results.append(ForgeTestResult(
                    test_name=m.group(2),
                    passed=m.group(1) == "PASS",
                    gas_used=int(m.group(3)),
                ))

        return results

    @staticmethod
    def _parse_coverage(stdout: str) -> list[ForgeCoverageEntry]:
        """Parse the ``forge coverage`` table output."""
        entries: list[ForgeCoverageEntry] = []
        # Table rows: | File | Lines | Branches | Funcs |
        # Each cell: "50.00% (5/10)"
        pct_re = re.compile(r"(\d+(?:\.\d+)?)%\s*\((\d+)/(\d+)\)")

        for line in stdout.splitlines():
            if not line.startswith("|") or "File" in line or "---" in line:
                continue
            cols = [c.strip() for c in line.split("|")]
            cols = [c for c in cols if c]
            if len(cols) < 4:
                continue

            file_name = cols[0]
            entry = ForgeCoverageEntry(file=file_name)

            for idx, attr_prefix in enumerate(
                [("lines_hit", "lines_total"),
                 ("branches_hit", "branches_total"),
                 ("functions_hit", "functions_total")],
                start=1,
            ):
                if idx < len(cols):
                    m = pct_re.search(cols[idx])
                    if m:
                        setattr(entry, attr_prefix[0], int(m.group(2)))
                        setattr(entry, attr_prefix[1], int(m.group(3)))

            entries.append(entry)

        return entries
