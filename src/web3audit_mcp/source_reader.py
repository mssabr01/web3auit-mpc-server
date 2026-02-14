"""Helpers for reading and analysing target Solidity source files.

These are used by the PoC generator to understand contract interfaces,
detect frameworks, and read relevant code.
"""

from __future__ import annotations

import re
from pathlib import Path

from .models import Finding


def read_contract_sources(
    project_path: Path, finding: Finding
) -> dict[str, str]:
    """Read all .sol files referenced by *finding*'s locations.

    Returns ``{relative_path: source_text}``.
    """
    sources: dict[str, str] = {}
    for loc in finding.locations:
        if not loc.file:
            continue
        fp = project_path / loc.file
        if fp.exists() and fp.suffix == ".sol":
            sources[loc.file] = fp.read_text(errors="replace")
    return sources


def read_file(project_path: Path, relative_path: str) -> str | None:
    """Read a single file, return contents or None."""
    fp = project_path / relative_path
    if fp.exists():
        return fp.read_text(errors="replace")
    return None


def extract_contract_interface(source: str, contract_name: str) -> list[str]:
    """Extract public/external function signatures from a contract.

    Returns a list of signature strings like
    ``"function withdraw(uint256 amount) external"``.
    """
    # Find the contract body
    pattern = re.compile(
        rf"(?:abstract\s+)?(?:contract|interface)\s+{re.escape(contract_name)}"
        r"\s*(?:is\s+[^{{]+)?\{{",
        re.MULTILINE,
    )
    m = pattern.search(source)
    if not m:
        return []

    # Extract body by brace-counting
    start = m.end() - 1
    depth, pos = 1, m.end()
    while pos < len(source) and depth > 0:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1
    body = source[start:pos]

    # Pull function signatures
    func_re = re.compile(
        r"function\s+(\w+)\s*\([^)]*\)\s*"
        r"((?:external|public|view|pure|payable|virtual|override|\w+\s*(?:\([^)]*\))?)\s*)*"
        r"(?:returns\s*\([^)]*\))?"
    )
    sigs: list[str] = []
    for fm in func_re.finditer(body):
        sig_text = fm.group(0).strip()
        # Only public / external
        if "external" in sig_text or "public" in sig_text:
            sigs.append(sig_text)

    return sigs


def detect_framework(project_path: Path) -> str:
    """Detect whether the project uses Foundry or Hardhat.

    Returns ``"foundry"`` | ``"hardhat"`` | ``"unknown"``.
    """
    if (project_path / "foundry.toml").exists():
        return "foundry"
    if (project_path / "hardhat.config.js").exists():
        return "hardhat"
    if (project_path / "hardhat.config.ts").exists():
        return "hardhat"
    return "unknown"


def list_solidity_files(
    project_path: Path,
    exclude: list[str] | None = None,
) -> list[str]:
    """Return relative paths of all .sol files under *project_path*."""
    exclude = exclude or []
    results: list[str] = []
    skip_dirs = {"node_modules", "lib", ".git", "out", "cache"}
    for sol in sorted(project_path.rglob("*.sol")):
        if any(part in sol.parts for part in skip_dirs):
            continue
        rel = str(sol.relative_to(project_path))
        if any(ex in rel for ex in exclude):
            continue
        results.append(rel)
    return results
