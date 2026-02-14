"""PoC generation engine — turns audit findings into Forge test contracts."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from ..models import AuditConfig, Finding
from .models import PoCArtifact
from .strategies import StrategyRegistry, build_default_registry

logger = logging.getLogger(__name__)


class PoCGenerator:
    """Generate Solidity PoC test contracts from audit findings."""

    def __init__(self, registry: StrategyRegistry | None = None) -> None:
        self.strategies = registry or build_default_registry()

    # ------------------------------------------------------------------

    def generate_for_finding(
        self,
        finding: Finding,
        project_path: Path,
        solc_version: str = "0.8.24",
        strategy_name: str | None = None,
    ) -> PoCArtifact | None:
        """Generate a single PoC for *finding*.

        Args:
            finding: The vulnerability to prove.
            project_path: Root of the Solidity project (to read sources).
            solc_version: Compiler version for the test.
            strategy_name: Force a specific strategy (auto-detect if None).

        Returns:
            A ``PoCArtifact`` with the test source, or ``None`` if no
            strategy matches.
        """
        if strategy_name:
            strategy = self.strategies.get_by_name(strategy_name)
            if strategy is None:
                logger.warning("Strategy %r not found", strategy_name)
                return None
        else:
            candidates = self.strategies.get_applicable(finding)
            strategy = candidates[0]  # best match (generic as fallback)

        sources = self._read_sources(project_path, finding)

        try:
            poc = strategy.generate(finding, sources, solc_version)
            logger.info(
                "Generated PoC %s for finding %s (%s)",
                poc.poc_id, finding.id, strategy.name,
            )
            return poc
        except Exception:
            logger.exception(
                "Strategy %s failed for finding %s", strategy.name, finding.id
            )
            return None

    async def generate_batch(
        self,
        findings: list[Finding],
        project_path: Path,
        solc_version: str = "0.8.24",
    ) -> list[PoCArtifact]:
        """Generate PoCs for multiple findings concurrently."""
        loop = asyncio.get_running_loop()
        tasks = [
            loop.run_in_executor(
                None,
                self.generate_for_finding,
                f, project_path, solc_version, None,
            )
            for f in findings
        ]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_sources(
        project_path: Path, finding: Finding
    ) -> dict[str, str]:
        """Read source files referenced by the finding's locations."""
        sources: dict[str, str] = {}
        for loc in finding.locations:
            if not loc.file:
                continue
            fp = project_path / loc.file
            if fp.exists() and fp.suffix == ".sol":
                sources[loc.file] = fp.read_text(errors="replace")
        return sources
