"""Kiểu dữ liệu dùng chung cho verifier (Layer 3)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VerifierResult:
    """Kết quả xác minh một candidate sink qua model GraphCodeBERT (ONNX).

    status:
        "ML_NOT_SUPPORTED"     — ngôn ngữ không thuộc SUPPORTED_ML_LANGUAGES,
                                  model không được gọi (ml_verified=False).
        "OK"                   — xác suất nằm ngoài uncertain_zone của ngôn ngữ.
        "UNCERTAIN_NEEDS_REVIEW" — xác suất rơi vào uncertain_zone, cần review thủ công.
    """

    ml_verified: bool
    confidence: float | None
    label: int | None
    status: str
