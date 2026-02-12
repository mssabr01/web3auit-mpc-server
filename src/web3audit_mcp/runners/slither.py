"""Runner for Trail of Bits Slither static analyser."""

from __future__ import annotations

import json
import logging
import tempfile
from pathlib import Path

from ..models import (
    AuditConfig,
    Confidence,
    Finding,
    Severity,
    SourceLocation,
    SourceTool,
)
from .base import BaseRunner

logger = logging.getLogger(__name__)

# Slither impact/confidence strings → our enums
_SEV_MAP: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Optimization": Severity.INFORMATIONAL,
}
_CONF_MAP: dict[str, Confidence] = {
    "High": Confidence.HIGH,
    "Medium": Confidence.MEDIUM,
    "Low": Confidence.LOW,
}

# Detectors whose presence almost always warrants Critical
_CRITICAL_DETECTORS = frozenset({
    "suicidal",
    "unprotected-upgrade",
    "arbitrary-send-erc20",
    "arbitrary-send-eth",
    "controlled-delegatecall",
    "delegatecall-loop",
    "msg-value-loop",
    "reentrancy-eth",
    "unchecked-transfer",
})


class SlitherRunner(BaseRunner):
    name = "slither"

    async def run(self, config: AuditConfig) -> list[Finding]:
        project = config.project_path
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        cmd: list[str] = [
            "slither", project,
            "--json", out_path,
        ]
        if config.solc_version:
            cmd += ["--solc-select", config.solc_version]
        for p in config.exclude_paths:
            cmd += ["--filter-paths", p]
        cmd += config.extra_slither_args

        try:
            _stdout, stderr, rc = await self._exec(
                cmd, cwd=project, timeout=config.slither_timeout
            )
        except TimeoutError as exc:
            logger.warning(str(exc))
            return []

        # Slither exits non-zero when it finds issues — that's expected
        if rc not in (0, 1, 255):
            logger.error("slither exited %d: %s", rc, stderr[:500])
            return []

        return self._parse(out_path)

    # -----------------------------------------------------------------------

    def _parse(self, json_path: str) -> list[Finding]:
        raw = Path(json_path).read_text()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.error("Failed to parse slither JSON output")
            return []

        results: list[dict] = data.get("results", {}).get("detectors", [])
        findings: list[Finding] = []

        for det in results:
            detector_name = det.get("check", "unknown")
            impact = det.get("impact", "Informational")
            confidence = det.get("confidence", "Medium")
            description = det.get("description", "")

            severity = _SEV_MAP.get(impact, Severity.INFORMATIONAL)
            # Promote to critical for known dangerous detectors
            if detector_name in _CRITICAL_DETECTORS and severity.rank > Severity.CRITICAL.rank:
                severity = Severity.CRITICAL

            locations = self._extract_locations(det.get("elements", []))
            reference = det.get("wiki_url") or det.get("wiki", "")

            findings.append(Finding(
                title=det.get("title", detector_name),
                detector=f"slither:{detector_name}",
                severity=severity,
                confidence=_CONF_MAP.get(confidence, Confidence.MEDIUM),
                source_tool=SourceTool.SLITHER,
                description=description.strip(),
                locations=locations,
                recommendation=det.get("recommendation", ""),
                references=[reference] if reference else [],
                raw=det,
            ))

        return findings

    @staticmethod
    def _extract_locations(elements: list[dict]) -> list[SourceLocation]:
        locs: list[SourceLocation] = []
        for el in elements:
            src = el.get("source_mapping", {})
            filename = src.get("filename_relative") or src.get("filename_short", "")
            lines = src.get("lines", [])
            locs.append(SourceLocation(
                file=filename,
                contract=el.get("type_specific_fields", {}).get("parent", {}).get("name"),
                function=(
                    el.get("name")
                    if el.get("type") in ("function", "modifier")
                    else None
                ),
                line_start=min(lines) if lines else None,
                line_end=max(lines) if lines else None,
            ))
        return locs
