"""web3audit MCP server — one-shot audits, individual tools, dedup, reports.

Exposes the following MCP tools:

  audit            Full pipeline: run tools → dedup → report
  run_slither      Run only Slither
  run_aderyn       Run only Aderyn
  run_custom       Run only custom DeFi detectors
  list_detectors   List registered custom detectors
  generate_report  Re-render the last audit result as Markdown
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from .dedup import deduplicate
from .detectors import DetectorRegistry
from .detectors.registry import get_registry
from .models import AuditConfig, AuditResult, Finding, Severity, SourceTool
from .report import generate_report
from .runners.aderyn import AderynRunner
from .runners.slither import SlitherRunner

# Force detector registration (side-effect imports)
import web3audit_mcp.detectors.flash_loan  # noqa: F401
import web3audit_mcp.detectors.oracle_manipulation  # noqa: F401
import web3audit_mcp.detectors.price_manipulation  # noqa: F401
import web3audit_mcp.detectors.unchecked_low_level  # noqa: F401

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(name)s  %(message)s")
logger = logging.getLogger("web3audit_mcp")

# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------
mcp = FastMCP(
    "web3audit-mcp",
    instructions=(
        "Smart-contract auditing server: orchestrates Slither, Aderyn, and "
        "custom DeFi detectors with cross-tool deduplication and structured reports."
    ),
)

# Shared state (last audit result, for report regeneration)
_last_result: AuditResult | None = None

# Runner singletons
_slither = SlitherRunner()
_aderyn = AderynRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _config_from_args(args: dict[str, Any]) -> AuditConfig:
    """Build an AuditConfig from the raw tool arguments."""
    return AuditConfig(
        project_path=args.get("project_path", "/contracts"),
        run_slither=args.get("run_slither", True),
        run_aderyn=args.get("run_aderyn", True),
        run_custom=args.get("run_custom", True),
        custom_detectors=args.get("custom_detectors"),
        slither_timeout=args.get("slither_timeout", 300),
        aderyn_timeout=args.get("aderyn_timeout", 300),
        solc_version=args.get("solc_version"),
        exclude_paths=args.get("exclude_paths", []),
        extra_slither_args=args.get("extra_slither_args", []),
        extra_aderyn_args=args.get("extra_aderyn_args", []),
    )


async def _run_pipeline(config: AuditConfig) -> AuditResult:
    """Core pipeline: run selected tools → collect → dedup → wrap."""
    global _last_result

    all_findings: list[Finding] = []
    errors: list[str] = []
    tools_ran: list[str] = []

    # ---- Phase 1: Run tools concurrently -----------------------------------
    tasks: dict[str, asyncio.Task] = {}
    if config.run_slither:
        tasks["slither"] = asyncio.create_task(_slither.run(config))
    if config.run_aderyn:
        tasks["aderyn"] = asyncio.create_task(_aderyn.run(config))
    if config.run_custom:
        registry = get_registry()
        tasks["custom"] = asyncio.create_task(
            registry.run_all(config, only=config.custom_detectors)
        )

    for name, task in tasks.items():
        try:
            results = await task
            all_findings.extend(results)
            tools_ran.append(name)
            logger.info("[%s] produced %d findings", name, len(results))
        except Exception as exc:
            msg = f"{name} failed: {exc}"
            logger.error(msg)
            errors.append(msg)

    # ---- Phase 2: Deduplicate across tools ---------------------------------
    deduped, n_removed = deduplicate(all_findings)
    logger.info("Dedup: %d findings → %d (removed %d)", len(all_findings), len(deduped), n_removed)

    result = AuditResult(
        project_path=config.project_path,
        findings=deduped,
        errors=errors,
        tools_ran=tools_ran,
        dedup_removed=n_removed,
    )
    _last_result = result
    return result


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def audit(
    project_path: str = "/contracts",
    run_slither: bool = True,
    run_aderyn: bool = True,
    run_custom: bool = True,
    custom_detectors: list[str] | None = None,
    slither_timeout: int = 300,
    aderyn_timeout: int = 300,
    solc_version: str | None = None,
    exclude_paths: list[str] = [],
    extra_slither_args: list[str] = [],
    extra_aderyn_args: list[str] = [],
) -> str:
    """Run a full smart-contract audit: Slither + Aderyn + custom detectors → dedup → Markdown report.

    This is the one-shot "audit this project" entry point.

    Args:
        project_path: Path to the Solidity project root (default: /contracts).
        run_slither: Whether to run Slither (default: true).
        run_aderyn: Whether to run Aderyn (default: true).
        run_custom: Whether to run custom DeFi detectors (default: true).
        custom_detectors: Subset of custom detectors to run (default: all).
        slither_timeout: Slither timeout in seconds.
        aderyn_timeout: Aderyn timeout in seconds.
        solc_version: Override solc version (e.g. "0.8.24").
        exclude_paths: File paths / patterns to exclude from analysis.
        extra_slither_args: Additional CLI args forwarded to Slither.
        extra_aderyn_args: Additional CLI args forwarded to Aderyn.

    Returns:
        A full Markdown audit report.
    """
    config = AuditConfig(
        project_path=project_path,
        run_slither=run_slither,
        run_aderyn=run_aderyn,
        run_custom=run_custom,
        custom_detectors=custom_detectors,
        slither_timeout=slither_timeout,
        aderyn_timeout=aderyn_timeout,
        solc_version=solc_version,
        exclude_paths=exclude_paths,
        extra_slither_args=extra_slither_args,
        extra_aderyn_args=extra_aderyn_args,
    )
    result = await _run_pipeline(config)
    return generate_report(result)


@mcp.tool()
async def run_slither(
    project_path: str = "/contracts",
    timeout: int = 300,
    solc_version: str | None = None,
    exclude_paths: list[str] = [],
    extra_args: list[str] = [],
) -> str:
    """Run only Slither on a project and return findings as JSON.

    Args:
        project_path: Path to the Solidity project root.
        timeout: Timeout in seconds.
        solc_version: Override solc version.
        exclude_paths: Paths to exclude.
        extra_args: Additional Slither CLI arguments.
    """
    config = AuditConfig(
        project_path=project_path,
        slither_timeout=timeout,
        solc_version=solc_version,
        exclude_paths=exclude_paths,
        extra_slither_args=extra_args,
    )
    findings = await _slither.run(config)
    return json.dumps(
        [f.model_dump(exclude={"raw"}) for f in findings],
        indent=2,
    )


@mcp.tool()
async def run_aderyn(
    project_path: str = "/contracts",
    timeout: int = 300,
    exclude_paths: list[str] = [],
    extra_args: list[str] = [],
) -> str:
    """Run only Aderyn on a project and return findings as JSON.

    Args:
        project_path: Path to the Solidity project root.
        timeout: Timeout in seconds.
        exclude_paths: Paths to exclude.
        extra_args: Additional Aderyn CLI arguments.
    """
    config = AuditConfig(
        project_path=project_path,
        aderyn_timeout=timeout,
        exclude_paths=exclude_paths,
        extra_aderyn_args=extra_args,
    )
    findings = await _aderyn.run(config)
    return json.dumps(
        [f.model_dump(exclude={"raw"}) for f in findings],
        indent=2,
    )


@mcp.tool()
async def run_custom(
    project_path: str = "/contracts",
    detectors: list[str] | None = None,
    exclude_paths: list[str] = [],
) -> str:
    """Run only the custom DeFi detectors and return findings as JSON.

    Args:
        project_path: Path to the Solidity project root.
        detectors: Subset of detector names to run (default: all).
        exclude_paths: Paths to exclude.
    """
    config = AuditConfig(
        project_path=project_path,
        custom_detectors=detectors,
        exclude_paths=exclude_paths,
    )
    registry = get_registry()
    findings = await registry.run_all(config, only=detectors)
    return json.dumps(
        [f.model_dump(exclude={"raw"}) for f in findings],
        indent=2,
    )


@mcp.tool()
async def list_detectors() -> str:
    """List all registered custom detectors with their descriptions and tags."""
    registry = get_registry()
    detectors = []
    for d in registry.all:
        detectors.append({
            "name": d.name,
            "description": d.description,
            "tags": d.tags,
        })
    return json.dumps(detectors, indent=2)


@mcp.tool()
async def regenerate_report() -> str:
    """Re-render the Markdown report from the last audit run.

    Useful if you want to re-read the report without re-running analysis.
    """
    if _last_result is None:
        return "No audit result cached. Run `audit` first."
    return generate_report(_last_result)


@mcp.tool()
async def get_audit_json() -> str:
    """Return the last audit result as raw JSON (for programmatic consumption)."""
    if _last_result is None:
        return json.dumps({"error": "No audit result cached. Run `audit` first."})
    return _last_result.model_dump_json(indent=2, exclude={"findings": {"__all__": {"raw"}}})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
