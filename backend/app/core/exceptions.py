"""Domain-specific exceptions for TRUST-CV."""
from typing import Any, Dict, Optional


class TrustCVException(Exception):
    """Base exception for all TRUST-CV errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class IntegrityViolationError(TrustCVException):
    """Raised when cryptographic digest or signature verification fails."""
    pass


class TamperingDetectedError(TrustCVException):
    """Raised when an asset, record, or model has been manipulated."""
    pass


class ReplayAttackDetectedError(TrustCVException):
    """Raised when a replayed inference, duplicate nonce, or invalid sequence is detected."""
    pass


class EntityNotFoundError(TrustCVException):
    """Raised when an asset (dataset, sample, model, inference) cannot be found."""
    pass


class ModelAdapterError(TrustCVException):
    """Raised when a model cannot be inspected or executed via adapter."""
    pass


class DatasetFormatError(TrustCVException):
    """Raised when dataset structure does not match expected format."""
    pass


class AirGappedViolationError(TrustCVException):
    """Raised if any operation attempts disallowed external network calls."""
    pass
