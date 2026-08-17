"""
verifier: Module AI inference sử dụng ONNX Runtime để xác minh (verify) các
candidate finding do rule engine (parsers/) phát hiện, nhằm giảm false positive.

Model (GraphCodeBERT, fine-tuned) chỉ hỗ trợ 3 ngôn ngữ: C, C++, Java —
xem SUPPORTED_ML_LANGUAGES. Ngôn ngữ khác không được đưa qua model.
"""

from __future__ import annotations

from pathlib import Path

WEIGHTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "weights"

SUPPORTED_ML_LANGUAGES = ["c", "cpp", "java"]

DEFAULT_MODEL_PATH = WEIGHTS_DIR / "model.onnx"
DEFAULT_TOKENIZER_PATH = WEIGHTS_DIR / "tokenizer"
DEFAULT_THRESHOLD_CONFIG_PATH = WEIGHTS_DIR / "threshold_config.json"

from vulneracheck.verifier.types import VerifierResult  # noqa: E402
from vulneracheck.verifier.inference import ONNXVerifier  # noqa: E402

__all__ = [
    "SUPPORTED_ML_LANGUAGES",
    "WEIGHTS_DIR",
    "DEFAULT_MODEL_PATH",
    "DEFAULT_TOKENIZER_PATH",
    "DEFAULT_THRESHOLD_CONFIG_PATH",
    "ONNXVerifier",
    "VerifierResult",
]
