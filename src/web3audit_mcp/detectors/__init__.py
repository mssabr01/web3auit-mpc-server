"""Custom smart-contract detectors."""

from .registry import DetectorRegistry, BaseDetector
from .flash_loan import FlashLoanDetector
from .oracle_manipulation import OracleManipulationDetector
from .price_manipulation import PriceManipulationDetector
from .unchecked_low_level import UncheckedLowLevelDetector

__all__ = [
    "DetectorRegistry",
    "BaseDetector",
    "FlashLoanDetector",
    "OracleManipulationDetector",
    "PriceManipulationDetector",
    "UncheckedLowLevelDetector",
]
