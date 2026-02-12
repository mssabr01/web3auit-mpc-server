"""Base runner interface for external auditing tools."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from pathlib import Path

from ..models import AuditConfig, Finding

logger = logging.getLogger(__name__)


class BaseRunner(ABC):
    """Contract every tool runner must satisfy."""

    name: str  # e.g. "slither", "aderyn"

    @abstractmethod
    async def run(self, config: AuditConfig) -> list[Finding]:
        """Execute the tool and return normalised findings."""

    # --- shared helpers -----------------------------------------------------

    async def _exec(
        self,
        cmd: list[str],
        *,
        cwd: str | Path,
        timeout: int,
        env: dict[str, str] | None = None,
    ) -> tuple[str, str, int]:
        """Run *cmd* as a subprocess with a timeout.

        Returns (stdout, stderr, returncode).
        """
        logger.info("[%s] running: %s (timeout=%ds)", self.name, " ".join(cmd), timeout)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd),
            env=env,
        )
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            raise TimeoutError(
                f"{self.name} timed out after {timeout}s on {cwd}"
            )
        stdout = stdout_b.decode(errors="replace")
        stderr = stderr_b.decode(errors="replace")
        logger.debug("[%s] rc=%d  stdout=%d chars  stderr=%d chars",
                     self.name, proc.returncode or 0, len(stdout), len(stderr))
        return stdout, stderr, proc.returncode or 0
