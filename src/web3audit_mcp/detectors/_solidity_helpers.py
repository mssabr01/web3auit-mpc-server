"""Shared Solidity source-scanning helpers used by multiple detectors."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SolFunction:
    """Minimal representation of a Solidity function found via regex."""

    name: str
    contract: str
    file: str
    line_start: int
    line_end: int
    body: str
    visibility: str  # "public", "external", "internal", "private"
    modifiers: list[str]


# Regex for extracting top-level contract/library/interface declarations
_CONTRACT_RE = re.compile(
    r"(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)", re.MULTILINE
)

# Regex for function declarations (captures up to the opening brace)
_FUNC_RE = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*((?:public|external|internal|private|view|pure|payable|virtual|override|\w+\s*(?:\([^)]*\))?)\s*)*\{",
    re.MULTILINE,
)

_VISIBILITY_KW = {"public", "external", "internal", "private"}


def iter_solidity_files(project: Path, exclude: list[str] | None = None) -> list[Path]:
    """Yield all .sol files under *project*, honouring exclusions."""
    exclude = exclude or []
    files: list[Path] = []
    for sol in project.rglob("*.sol"):
        rel = str(sol.relative_to(project))
        if any(ex in rel for ex in exclude):
            continue
        # Skip common non-source dirs
        if any(part in sol.parts for part in ("node_modules", "lib", ".git")):
            continue
        files.append(sol)
    return files


def extract_functions(filepath: Path) -> list[SolFunction]:
    """Quick-and-dirty function extraction via regex.

    This is intentionally simple — it doesn't need to be a full parser for
    the pattern-matching detectors to work.  For complex analysis, delegate
    to Slither's AST.
    """
    source = filepath.read_text(errors="replace")
    lines = source.splitlines()

    # Find contract spans
    contracts: list[tuple[str, int, int]] = []
    for m in _CONTRACT_RE.finditer(source):
        start_line = source[:m.start()].count("\n") + 1
        contracts.append((m.group(1), start_line, 0))

    funcs: list[SolFunction] = []

    for m in _FUNC_RE.finditer(source):
        func_name = m.group(1)
        func_line = source[:m.start()].count("\n") + 1

        # Find the enclosing contract
        contract_name = "Unknown"
        for cname, cstart, _ in reversed(contracts):
            if cstart <= func_line:
                contract_name = cname
                break

        # Extract body by brace-counting from the opening {
        brace_start = m.end() - 1  # position of {
        depth, pos = 1, m.end()
        while pos < len(source) and depth > 0:
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
            pos += 1
        body = source[brace_start:pos]
        end_line = source[:pos].count("\n") + 1

        # Parse visibility and modifiers from the signature
        sig_text = source[m.start():m.end()]
        vis = "internal"  # Solidity default
        modifiers: list[str] = []
        for token in sig_text.split():
            if token in _VISIBILITY_KW:
                vis = token
            elif token not in ("function", func_name, "{", "returns", "view", "pure", "payable", "virtual", "override"):
                cleaned = token.strip("()")
                if cleaned and cleaned.isidentifier():
                    modifiers.append(cleaned)

        funcs.append(SolFunction(
            name=func_name,
            contract=contract_name,
            file=str(filepath),
            line_start=func_line,
            line_end=end_line,
            body=body,
            visibility=vis,
            modifiers=modifiers,
        ))

    return funcs
