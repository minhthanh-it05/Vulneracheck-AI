"""Shared data types for the verifier (Layer 3)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VerifierResult:
    """Result of verifying a candidate sink through the GraphCodeBERT (ONNX) model.

    status:
        "ML_NOT_SUPPORTED"       — language is not in SUPPORTED_ML_LANGUAGES,
                                    the model was not called (ml_verified=False).
        "OK"                     — probability falls outside the language's uncertain_zone.
        "UNCERTAIN_NEEDS_REVIEW" — probability falls within the uncertain_zone, needs manual review.
    """

    ml_verified: bool
    confidence: float | None
    label: int | None
    status: str
