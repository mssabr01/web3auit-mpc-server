"""Detector registry — discover and run custom detectors."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from ..models import AuditConfig, Finding

logger = logging.getLogger(__name__)


class BaseDetector(ABC):
    """Every custom detector inherits from this."""

    name: str  # unique slug, e.g. "flash-loan"
    description: str = ""
    tags: list[str] = []

    @abstractmethod
    async def detect(self, project_path: Path, config: AuditConfig) -> list[Finding]:
        """Scan source files and return findings."""


class DetectorRegistry:
    """Auto-discovers and manages detector instances."""

    def __init__(self) -> None:
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        self._detectors[detector.name] = detector
        logger.debug("Registered custom detector: %s", detector.name)

    def get(self, name: str) -> BaseDetector | None:
        return self._detectors.get(name)

    @property
    def all(self) -> list[BaseDetector]:
        return list(self._detectors.values())

    def names(self) -> list[str]:
        return list(self._detectors.keys())

    async def run_all(
        self,
        config: AuditConfig,
        *,
        only: list[str] | None = None,
    ) -> list[Finding]:
        """Run selected (or all) detectors and collect findings."""
        findings: list[Finding] = []
        project = Path(config.project_path)

        for det in self._detectors.values():
            if only is not None and det.name not in only:
                continue
            try:
                logger.info("Running custom detector: %s", det.name)
                results = await det.detect(project, config)
                findings.extend(results)
                logger.info("  → %d findings", len(results))
            except Exception:
                logger.exception("Custom detector %s failed", det.name)

        return findings


# ---------------------------------------------------------------------------
# Singleton registry with built-in detectors pre-registered
# ---------------------------------------------------------------------------
_registry = DetectorRegistry()


def get_registry() -> DetectorRegistry:
    return _registry
