"""Temporary Forge project lifecycle management.

Creates isolated Forge projects to compile and run PoC tests without
touching the original contract repo.
"""

from __future__ import annotations

import hashlib
import logging
import shutil
from pathlib import Path

from .models import PoCArtifact

logger = logging.getLogger(__name__)

_DEFAULT_CACHE = Path("/tmp/web3audit-poc")

# Path where forge-std is pre-cached in the Docker image
_FORGE_STD_CACHE = Path("/opt/forge-std-cache/lib/forge-std")


class ForgeProjectManager:
    """Create, populate, and clean up temporary Forge projects."""

    def __init__(self, cache_dir: Path = _DEFAULT_CACHE) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_project(
        self,
        poc_artifacts: list[PoCArtifact],
        source_project: Path,
        solc_version: str = "0.8.24",
    ) -> Path:
        """Build a ready-to-compile Forge project containing the PoC tests.

        Layout::

            <project_dir>/
            ├── foundry.toml
            ├── lib/
            │   └── forge-std/    (symlinked or copied from cache)
            ├── src/              (relevant source files from target project)
            └── test/             (generated PoC .t.sol files)
        """
        project_id = self._project_hash(poc_artifacts)
        project_dir = self.cache_dir / project_id

        if project_dir.exists():
            logger.info("Reusing cached PoC project: %s", project_dir)
            return project_dir

        logger.info("Creating PoC project: %s", project_dir)
        project_dir.mkdir(parents=True)
        (project_dir / "src").mkdir()
        (project_dir / "test").mkdir()
        (project_dir / "lib").mkdir()

        # 1. Link forge-std
        self._link_forge_std(project_dir)

        # 2. Copy source files referenced by PoCs
        copied: set[str] = set()
        for poc in poc_artifacts:
            self._copy_sources_for_poc(poc, source_project, project_dir, copied)

        # 3. Write PoC test files
        for poc in poc_artifacts:
            test_path = project_dir / poc.test_file_path
            test_path.parent.mkdir(parents=True, exist_ok=True)
            test_path.write_text(poc.solidity_code)

        # 4. Copy remappings if they exist
        for name in ("remappings.txt", "remappings"):
            src = source_project / name
            if src.exists():
                shutil.copy2(src, project_dir / name)

        # 5. Write foundry.toml
        self._write_config(project_dir, solc_version, source_project)

        return project_dir

    def cleanup(self, project_dir: Path) -> None:
        """Delete a single cached project."""
        if project_dir.exists() and self.cache_dir in project_dir.parents:
            shutil.rmtree(project_dir, ignore_errors=True)
            logger.info("Cleaned up %s", project_dir)

    def cleanup_all(self) -> None:
        """Delete the entire PoC cache."""
        if self.cache_dir.exists():
            shutil.rmtree(self.cache_dir, ignore_errors=True)
            self.cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _project_hash(pocs: list[PoCArtifact]) -> str:
        blob = "|".join(sorted(p.poc_id for p in pocs))
        return hashlib.sha256(blob.encode()).hexdigest()[:16]

    @staticmethod
    def _link_forge_std(project_dir: Path) -> None:
        """Symlink forge-std from Docker cache, or fall back to empty dir."""
        target = project_dir / "lib" / "forge-std"
        if _FORGE_STD_CACHE.exists():
            target.symlink_to(_FORGE_STD_CACHE)
        else:
            # Fallback: forge will need to install it
            target.mkdir(parents=True, exist_ok=True)
            logger.warning(
                "forge-std cache not found at %s — "
                "run `forge install` in the PoC project before testing",
                _FORGE_STD_CACHE,
            )

    @staticmethod
    def _copy_sources_for_poc(
        poc: PoCArtifact,
        source_project: Path,
        project_dir: Path,
        already_copied: set[str],
    ) -> None:
        """Copy .sol files from the target project that the PoC imports."""
        # Walk all .sol files in the source project (simple approach)
        # A smarter version would parse import graphs.
        for sol in source_project.rglob("*.sol"):
            rel = str(sol.relative_to(source_project))
            if rel in already_copied:
                continue
            # Skip test/lib dirs from the source project
            if any(part in sol.parts for part in ("test", "node_modules", ".git")):
                continue
            dst = project_dir / "src" / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(sol, dst)
            already_copied.add(rel)

    @staticmethod
    def _write_config(
        project_dir: Path,
        solc_version: str,
        source_project: Path,
    ) -> None:
        """Write foundry.toml for the PoC project."""
        # Detect if source project has remappings to carry over
        remappings_line = ""
        remap_file = source_project / "remappings.txt"
        if remap_file.exists():
            lines = remap_file.read_text().strip().splitlines()
            quoted = ", ".join(f'"{l.strip()}"' for l in lines if l.strip())
            remappings_line = f"remappings = [{quoted}]"

        config = f"""\
[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
solc_version = "{solc_version}"
optimizer = true
optimizer_runs = 200
ffi = false
{remappings_line}

[profile.default.fuzz]
runs = 256
"""
        (project_dir / "foundry.toml").write_text(config)
