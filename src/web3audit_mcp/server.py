"""web3audit MCP server — one-shot audits, individual tools, dedup, reports.

Exposes the following MCP tools:

  Audit pipeline
  ──────────────
  audit              Full pipeline: run tools → dedup → report
  run_slither        Run only Slither
  run_aderyn         Run only Aderyn
  run_custom         Run only custom DeFi detectors
  list_detectors     List registered custom detectors
  regenerate_report  Re-render the last audit result as Markdown
  get_audit_json     Raw JSON of last audit

  PoC / validation
  ────────────────
  generate_poc       Generate a Forge test PoC for one finding
  run_forge_test     Run forge tests in any project
  validate_finding   End-to-end: generate → compile → test → report
  run_forge_coverage Run forge coverage
  list_poc_strategies List available PoC strategies
  read_contract_source Read a Solidity file (for agent inspection)
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from .dedup import deduplicate
from .detectors import DetectorRegistry
from .detectors.registry import get_registry
from .forge.runner import ForgeRunner
from .models import AuditConfig, AuditResult, Finding, Severity, SourceTool
from .poc.generator import PoCGenerator
from .poc.models import PoCArtifact, PoEResult
from .poc.project_manager import ForgeProjectManager
from .poc.strategies import build_default_registry
from .report import generate_report
from .runners.aderyn import AderynRunner
from .runners.slither import SlitherRunner
from . import source_reader

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
        "custom DeFi detectors with cross-tool deduplication and structured reports. "
        "Also generates and runs Forge-based PoC tests to prove findings exploitable."
    ),
)

# Shared state
_last_result: AuditResult | None = None
_last_pocs: dict[str, PoCArtifact] = {}  # finding_id → PoCArtifact

# Singletons
_slither = SlitherRunner()
_aderyn = AderynRunner()
_forge = ForgeRunner()
_poc_gen = PoCGenerator(build_default_registry())
_project_mgr = ForgeProjectManager()


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
# PoC / Forge Tools
# ---------------------------------------------------------------------------

def _find_by_id(finding_id: str) -> Finding | None:
    """Look up a finding from the last audit result."""
    if _last_result is None:
        return None
    for f in _last_result.findings:
        if f.id == finding_id:
            return f
    return None


@mcp.tool()
async def generate_poc(
    finding_id: str,
    project_path: str = "/contracts",
    solc_version: str = "0.8.24",
    strategy: str | None = None,
) -> str:
    """Generate a Proof-of-Concept Forge test for an audit finding.

    Args:
        finding_id: ID of the finding (from the last audit run).
        project_path: Path to the Solidity project root.
        solc_version: Solidity compiler version for the test.
        strategy: Force a specific strategy name (auto-detect if omitted).

    Returns:
        JSON with the PoCArtifact including the generated Solidity test source.
    """
    finding = _find_by_id(finding_id)
    if finding is None:
        return json.dumps({"error": f"Finding {finding_id!r} not found. Run `audit` first."})

    poc = _poc_gen.generate_for_finding(
        finding, Path(project_path), solc_version, strategy,
    )
    if poc is None:
        return json.dumps({"error": f"No applicable PoC strategy for detector {finding.detector!r}."})

    _last_pocs[finding_id] = poc
    return poc.model_dump_json(indent=2)


@mcp.tool()
async def run_forge_test(
    project_path: str,
    test_filter: str | None = None,
    fork_url: str | None = None,
    fork_block: int | None = None,
    verbosity: int = 2,
    timeout: int = 300,
) -> str:
    """Run ``forge test`` in a project and return structured results.

    This is a general-purpose Forge test runner — works on any Forge project,
    not just generated PoCs.

    Args:
        project_path: Path to the Forge project root.
        test_filter: Regex to filter test names (e.g. "test_reentrancy").
        fork_url: RPC URL to fork mainnet (enables fork-based testing).
        fork_block: Block number to fork at (latest if omitted).
        verbosity: 0-5 (more = more trace output).
        timeout: Timeout in seconds.

    Returns:
        JSON array of ForgeTestResult objects.
    """
    results = await _forge.test(
        Path(project_path),
        test_filter=test_filter,
        fork_url=fork_url,
        fork_block=fork_block,
        verbosity=verbosity,
        timeout=timeout,
    )
    return json.dumps([r.model_dump() for r in results], indent=2)


@mcp.tool()
async def validate_finding(
    finding_id: str,
    project_path: str = "/contracts",
    solc_version: str = "0.8.24",
    strategy: str | None = None,
    fork_url: str | None = None,
    fork_block: int | None = None,
    cleanup: bool = False,
) -> str:
    """End-to-end: generate PoC → compile → run test → report exploitability.

    This is the high-level tool an agent uses to prove a finding is real.

    Args:
        finding_id: ID of the finding to validate.
        project_path: Path to the Solidity project root.
        solc_version: Solidity compiler version.
        strategy: Force a PoC strategy (auto-detect if omitted).
        fork_url: Optional RPC URL for mainnet-fork testing.
        fork_block: Block number to fork at.
        cleanup: Delete the temporary Forge project after testing.

    Returns:
        JSON PoEResult with compile output, test results, and proven_exploitable flag.
    """
    finding = _find_by_id(finding_id)
    if finding is None:
        return json.dumps({"error": f"Finding {finding_id!r} not found. Run `audit` first."})

    # 1. Generate PoC
    poc = _last_pocs.get(finding_id) or _poc_gen.generate_for_finding(
        finding, Path(project_path), solc_version, strategy,
    )
    if poc is None:
        return PoEResult(
            finding_id=finding_id,
            finding_title=finding.title,
            poc=PoCArtifact(
                finding_id=finding_id, finding_title=finding.title,
                detector=finding.detector, strategy="none",
                test_contract_name="", test_function_name="",
                test_file_path="", solidity_code="",
            ),
            overall_status="error",
            error_message=f"No PoC strategy for {finding.detector}",
        ).model_dump_json(indent=2)

    _last_pocs[finding_id] = poc

    # 2. Create isolated Forge project
    forge_dir = _project_mgr.create_project(
        [poc], Path(project_path), solc_version,
    )

    # 3. Compile
    compile_result = await _forge.compile(forge_dir, solc_version)
    if not compile_result.success:
        return PoEResult(
            finding_id=finding_id,
            finding_title=finding.title,
            poc=poc,
            compile_result=compile_result,
            overall_status="compile_failed",
            error_message=compile_result.stderr[:2000],
            forge_project_path=str(forge_dir),
        ).model_dump_json(indent=2)

    # 4. Run tests
    test_results = await _forge.test(
        forge_dir,
        test_filter=poc.test_function_name,
        fork_url=fork_url,
        fork_block=fork_block,
    )

    any_passed = any(t.passed for t in test_results)
    all_passed = all(t.passed for t in test_results) and len(test_results) > 0

    result = PoEResult(
        finding_id=finding_id,
        finding_title=finding.title,
        poc=poc,
        compile_result=compile_result,
        test_results=test_results,
        proven_exploitable=any_passed,
        overall_status="success" if all_passed else "test_failed",
        forge_project_path=str(forge_dir),
    )

    # 5. Cleanup if requested
    if cleanup:
        _project_mgr.cleanup(forge_dir)

    return result.model_dump_json(indent=2)


@mcp.tool()
async def run_forge_coverage(
    project_path: str = "/contracts",
    timeout: int = 300,
) -> str:
    """Run ``forge coverage`` and return per-file coverage statistics.

    Args:
        project_path: Path to a Forge project root.
        timeout: Timeout in seconds.

    Returns:
        JSON array of coverage entries with line/branch/function stats.
    """
    entries = await _forge.coverage(Path(project_path), timeout=timeout)
    return json.dumps([e.model_dump() for e in entries], indent=2)


@mcp.tool()
async def list_poc_strategies() -> str:
    """List all available PoC generation strategies with their applicable detectors."""
    strategies = _poc_gen.strategies.all
    out = []
    for s in strategies:
        out.append({
            "name": s.name,
            "difficulty": s.difficulty,
            "applicable_detectors": sorted(s.applicable_detectors),
        })
    return json.dumps(out, indent=2)


@mcp.tool()
async def read_contract_source(
    project_path: str = "/contracts",
    file_path: str = "",
) -> str:
    """Read a Solidity source file from the project.

    Useful for an agent to inspect contract interfaces before writing PoCs.

    Args:
        project_path: Project root.
        file_path: Relative path to the .sol file (e.g. "src/Token.sol").
                   If empty, lists all .sol files in the project.

    Returns:
        The file contents, or a JSON list of available .sol files.
    """
    root = Path(project_path)
    if not file_path:
        files = source_reader.list_solidity_files(root)
        return json.dumps(files, indent=2)

    content = source_reader.read_file(root, file_path)
    if content is None:
        return json.dumps({"error": f"File not found: {file_path}"})
    return content


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
