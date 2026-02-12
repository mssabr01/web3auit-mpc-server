"""Runner for Cyfrin Aderyn static analyser."""

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

_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "nc": Severity.INFORMATIONAL,
}


class AderynRunner(BaseRunner):
    name = "aderyn"

    async def run(self, config: AuditConfig) -> list[Finding]:
        project = config.project_path

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out_path = tmp.name

        cmd: list[str] = [
            "aderyn", project,
            "--output", out_path,
        ]
        for p in config.exclude_paths:
            cmd += ["--exclude", p]
        cmd += config.extra_aderyn_args

        try:
            _stdout, stderr, rc = await self._exec(
                cmd, cwd=project, timeout=config.aderyn_timeout
            )
        except TimeoutError as exc:
            logger.warning(str(exc))
            return []

        if rc != 0:
            logger.error("aderyn exited %d: %s", rc, stderr[:500])
            return []

        return self._parse(out_path)

    # -----------------------------------------------------------------------

    def _parse(self, json_path: str) -> list[Finding]:
        raw = Path(json_path).read_text()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.error("Failed to parse aderyn JSON output")
            return []

        findings: list[Finding] = []

        # Aderyn groups findings under severity keys
        for sev_key, sev_enum in _SEV_MAP.items():
            issues = data.get(sev_key, data.get(f"{sev_key}_issues", {}))
            if isinstance(issues, dict):
                issues = issues.get("issues", [])
            if not isinstance(issues, list):
                continue

            for issue in issues:
                title = issue.get("title", "Unnamed issue")
                detector = issue.get("detector_name", "unknown")
                description = issue.get("description", "")

                locations = self._extract_locations(
                    issue.get("instances", issue.get("locations", []))
                )

                findings.append(Finding(
                    title=title,
                    detector=f"aderyn:{detector}",
                    severity=sev_enum,
                    confidence=Confidence.MEDIUM,
                    source_tool=SourceTool.ADERYN,
                    description=description.strip(),
                    locations=locations,
                    recommendation=issue.get("recommendation", ""),
                    references=[],
                    raw=issue,
                ))

        return findings

    @staticmethod
    def _extract_locations(instances: list[dict]) -> list[SourceLocation]:
        locs: list[SourceLocation] = []
        for inst in instances:
            # Aderyn uses "src" or "contract_path" depending on version
            filepath = (
                inst.get("contract_path")
                or inst.get("src", "")
                .split(":")[0]  # "path:offset:length"
            )
            locs.append(SourceLocation(
                file=filepath,
                contract=inst.get("contract_name"),
                function=inst.get("function_name"),
                line_start=inst.get("line_no") or inst.get("line"),
                line_end=inst.get("line_end"),
            ))
        return locs
