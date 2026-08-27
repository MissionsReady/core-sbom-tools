"""Deterministic SPDX evidence tooling for MissionsReady."""

from .core import (
    ContractError,
    build_evidence,
    compare_evidence,
    load_json_strict,
    validate_evidence,
)

__all__ = [
    "ContractError",
    "build_evidence",
    "compare_evidence",
    "load_json_strict",
    "validate_evidence",
]

__version__ = "1.0.0"
