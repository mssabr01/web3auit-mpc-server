"""PoC strategy registry — maps finding detectors to generation strategies."""

from __future__ import annotations

import logging
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Literal

from ..models import Finding
from .models import PoCArtifact
from .templates import interpolate

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------

class PoCStrategy(ABC):
    """Abstract base for PoC generation strategies."""

    name: str
    applicable_detectors: frozenset[str]  # exact or prefix matches
    difficulty: Literal["easy", "medium", "hard"] = "medium"

    def is_applicable(self, finding: Finding) -> bool:
        det = finding.detector
        for pattern in self.applicable_detectors:
            if det == pattern or det.startswith(pattern):
                return True
        return False

    @abstractmethod
    def generate(
        self,
        finding: Finding,
        sources: dict[str, str],
        solc_version: str,
    ) -> PoCArtifact:
        """Build a PoCArtifact from a finding + source context."""

    # -- helpers used by concrete strategies ---------------------------------

    @staticmethod
    def _primary_location(finding: Finding) -> tuple[str, str, str]:
        """Return (contract, function, file) from the first location."""
        loc = finding.locations[0] if finding.locations else None
        contract = (loc.contract if loc else None) or "Target"
        function = (loc.function if loc else None) or "vulnerableFunction"
        file = (loc.file if loc else None) or "Target.sol"
        return contract, function, file

    @staticmethod
    def _test_names(finding: Finding, strategy: str) -> tuple[str, str]:
        """Return (TestContractName, test_function_name)."""
        contract, func, _ = PoCStrategy._primary_location(finding)
        safe = re.sub(r"\W", "", contract)
        strat_safe = strategy.replace("-", "_")
        func_safe = re.sub(r"\W", "_", func)
        return (
            f"PoC_{safe}_{strat_safe}",
            f"test_{strat_safe}_{func_safe}",
        )


# ---------------------------------------------------------------------------
# Concrete strategies
# ---------------------------------------------------------------------------

class ReentrancyStrategy(PoCStrategy):
    name = "reentrancy"
    applicable_detectors = frozenset({
        "slither:reentrancy-eth",
        "slither:reentrancy-no-eth",
        "slither:reentrancy-benign",
        "slither:reentrancy-events",
        "slither:reentrancy-unlimited-gas",
        "aderyn:reentrancy",
        "aderyn:state-change-after-external-call",
    })
    difficulty: Literal["easy", "medium", "hard"] = "easy"

    def generate(self, finding: Finding, sources: dict[str, str], solc_version: str) -> PoCArtifact:
        contract, func, file = self._primary_location(finding)
        test_contract, test_func = self._test_names(finding, self.name)
        import_path = file.replace("\\", "/")

        code = interpolate(
            "reentrancy",
            solc_version=f"^{solc_version}",
            extra_imports=f'import "src/{import_path}";',
            target_contract_type=contract,
            target_function=func,
            call_args="",
            test_contract_name=test_contract,
            test_function_name=test_func,
            setup_code=f"target = new {contract}();",
            post_setup="vm.deal(address(target), 10 ether);",
        )
        return PoCArtifact(
            finding_id=finding.id,
            finding_title=finding.title,
            detector=finding.detector,
            strategy=self.name,
            test_contract_name=test_contract,
            test_function_name=test_func,
            test_file_path=f"test/{test_contract}.t.sol",
            solidity_code=code,
            solc_version=solc_version,
        )


class FlashLoanStrategy(PoCStrategy):
    name = "flash-loan"
    applicable_detectors = frozenset({
        "custom:flash-loan-unguarded-callback",
        "custom:flash-loan-balance-after-call",
    })
    difficulty: Literal["easy", "medium", "hard"] = "medium"

    def generate(self, finding: Finding, sources: dict[str, str], solc_version: str) -> PoCArtifact:
        contract, func, file = self._primary_location(finding)
        test_contract, test_func = self._test_names(finding, self.name)
        import_path = file.replace("\\", "/")

        code = interpolate(
            "flash-loan",
            solc_version=f"^{solc_version}",
            extra_imports=f'import "src/{import_path}";',
            target_contract_type=contract,
            target_function=func,
            call_args="",
            callback_args="",
            test_contract_name=test_contract,
            test_function_name=test_func,
            setup_code=f"target = new {contract}();",
            token="address(0)",
            loan_amount="1_000_000 ether",
            callback_name="onFlashLoan",
            snapshot_before=f"uint256 stateBefore = address(target).balance;",
            assertion_code="assertGt(address(this).balance, 0, \"Flash loan exploit failed\");",
        )
        return PoCArtifact(
            finding_id=finding.id,
            finding_title=finding.title,
            detector=finding.detector,
            strategy=self.name,
            test_contract_name=test_contract,
            test_function_name=test_func,
            test_file_path=f"test/{test_contract}.t.sol",
            solidity_code=code,
            solc_version=solc_version,
        )


class OracleManipulationStrategy(PoCStrategy):
    name = "oracle-manipulation"
    applicable_detectors = frozenset({
        "custom:oracle-spot-price",
        "custom:oracle-chainlink-stale",
        "custom:oracle-single-source",
    })
    difficulty: Literal["easy", "medium", "hard"] = "medium"

    def generate(self, finding: Finding, sources: dict[str, str], solc_version: str) -> PoCArtifact:
        contract, func, file = self._primary_location(finding)
        test_contract, test_func = self._test_names(finding, self.name)
        import_path = file.replace("\\", "/")

        code = interpolate(
            "oracle-manipulation",
            solc_version=f"^{solc_version}",
            extra_imports=f'import "src/{import_path}";',
            target_contract_type=contract,
            target_function=func,
            call_args="",
            test_contract_name=test_contract,
            test_function_name=test_func,
            setup_code=f"target = new {contract}();",
            price_before="uint256 priceBefore = 0; // TODO: read oracle price",
            manipulation_code="// TODO: mock oracle or manipulate reserves\nvm.mockCall(address(0), \"\", abi.encode(uint256(1)));",
            assertion_code="// TODO: verify exploit impact",
        )
        return PoCArtifact(
            finding_id=finding.id,
            finding_title=finding.title,
            detector=finding.detector,
            strategy=self.name,
            test_contract_name=test_contract,
            test_function_name=test_func,
            test_file_path=f"test/{test_contract}.t.sol",
            solidity_code=code,
            solc_version=solc_version,
        )


class PriceSlippageStrategy(PoCStrategy):
    name = "price-slippage"
    applicable_detectors = frozenset({
        "custom:price-zero-slippage",
        "custom:price-no-deadline",
    })
    difficulty: Literal["easy", "medium", "hard"] = "medium"

    def generate(self, finding: Finding, sources: dict[str, str], solc_version: str) -> PoCArtifact:
        contract, func, file = self._primary_location(finding)
        test_contract, test_func = self._test_names(finding, self.name)
        import_path = file.replace("\\", "/")

        code = interpolate(
            "price-slippage",
            solc_version=f"^{solc_version}",
            extra_imports=f'import "src/{import_path}";',
            target_contract_type=contract,
            target_function=func,
            call_args="",
            test_contract_name=test_contract,
            test_function_name=test_func,
            setup_code=f"target = new {contract}();",
            victim="address(0xBEEF)",
            frontrun_code="// TODO: manipulate pool price before victim tx",
            backrun_code="// TODO: swap back after victim tx to extract profit",
            assertion_code="// TODO: assert attacker profited",
        )
        return PoCArtifact(
            finding_id=finding.id,
            finding_title=finding.title,
            detector=finding.detector,
            strategy=self.name,
            test_contract_name=test_contract,
            test_function_name=test_func,
            test_file_path=f"test/{test_contract}.t.sol",
            solidity_code=code,
            solc_version=solc_version,
        )


class UncheckedCallStrategy(PoCStrategy):
    name = "unchecked-call"
    applicable_detectors = frozenset({
        "custom:unchecked-eth-transfer",
        "custom:delegatecall-defi",
        "slither:low-level-calls",
        "slither:unchecked-transfer",
        "aderyn:low-level-calls",
    })
    difficulty: Literal["easy", "medium", "hard"] = "easy"

    def generate(self, finding: Finding, sources: dict[str, str], solc_version: str) -> PoCArtifact:
        contract, func, file = self._primary_location(finding)
        test_contract, test_func = self._test_names(finding, self.name)
        import_path = file.replace("\\", "/")

        code = interpolate(
            "unchecked-call",
            solc_version=f"^{solc_version}",
            extra_imports=f'import "src/{import_path}";',
            target_contract_type=contract,
            target_function=func,
            call_args="",
            test_contract_name=test_contract,
            test_function_name=test_func,
            setup_code=f"target = new {contract}();",
            point_to_sink="// TODO: set recipient to address(sink)",
        )
        return PoCArtifact(
            finding_id=finding.id,
            finding_title=finding.title,
            detector=finding.detector,
            strategy=self.name,
            test_contract_name=test_contract,
            test_function_name=test_func,
            test_file_path=f"test/{test_contract}.t.sol",
            solidity_code=code,
            solc_version=solc_version,
        )


class GenericStrategy(PoCStrategy):
    """Fallback for any detector without a specialised strategy."""

    name = "generic"
    applicable_detectors = frozenset()  # matches nothing by default
    difficulty: Literal["easy", "medium", "hard"] = "hard"

    def is_applicable(self, finding: Finding) -> bool:
        return True  # always matches as fallback

    def generate(self, finding: Finding, sources: dict[str, str], solc_version: str) -> PoCArtifact:
        contract, func, file = self._primary_location(finding)
        test_contract, test_func = self._test_names(finding, "generic")
        import_path = file.replace("\\", "/")

        code = interpolate(
            "generic",
            solc_version=f"^{solc_version}",
            extra_imports=f'import "src/{import_path}";',
            target_contract_type=contract,
            target_function=func,
            call_args="",
            test_contract_name=test_contract,
            test_function_name=test_func,
            setup_code=f"target = new {contract}();",
            detector=finding.detector,
            pre_conditions="// TODO: set up initial state",
            assertion_code="// TODO: assert vulnerability impact",
        )
        return PoCArtifact(
            finding_id=finding.id,
            finding_title=finding.title,
            detector=finding.detector,
            strategy=self.name,
            test_contract_name=test_contract,
            test_function_name=test_func,
            test_file_path=f"test/{test_contract}.t.sol",
            solidity_code=code,
            solc_version=solc_version,
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class StrategyRegistry:
    """Lookup strategies by finding detector."""

    def __init__(self) -> None:
        self._strategies: list[PoCStrategy] = []
        self._fallback = GenericStrategy()

    def register(self, strategy: PoCStrategy) -> None:
        self._strategies.append(strategy)

    @property
    def all(self) -> list[PoCStrategy]:
        return list(self._strategies)

    def get_applicable(self, finding: Finding) -> list[PoCStrategy]:
        """Return matching strategies (best first), with generic fallback."""
        matches = [s for s in self._strategies if s.is_applicable(finding)]
        if not matches:
            matches = [self._fallback]
        return matches

    def get_by_name(self, name: str) -> PoCStrategy | None:
        for s in self._strategies:
            if s.name == name:
                return s
        if name == "generic":
            return self._fallback
        return None


# ---------------------------------------------------------------------------
# Default registry with all built-in strategies
# ---------------------------------------------------------------------------

def build_default_registry() -> StrategyRegistry:
    reg = StrategyRegistry()
    reg.register(ReentrancyStrategy())
    reg.register(FlashLoanStrategy())
    reg.register(OracleManipulationStrategy())
    reg.register(PriceSlippageStrategy())
    reg.register(UncheckedCallStrategy())
    return reg
