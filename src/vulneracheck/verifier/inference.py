"""
inference.py: Triển khai thật của Layer 3 — GraphCodeBERT (RoBERTa-based)
chạy qua ONNX Runtime để phân loại nhị phân an toàn/có lỗi cho từng candidate
sink, với threshold và uncertain-zone riêng theo từng ngôn ngữ.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

from vulneracheck.verifier.types import VerifierResult

MAX_SEQUENCE_LENGTH = 512

# Bí danh ngôn ngữ thường gặp -> tên chuẩn dùng trong threshold_config.json
_LANGUAGE_ALIASES = {
    "c++": "cpp",
    "cxx": "cpp",
    "cc": "cpp",
}


def _normalize_language(language: str) -> str:
    language = language.strip().lower()
    return _LANGUAGE_ALIASES.get(language, language)


def _softmax(logits: np.ndarray) -> np.ndarray:
    shifted = logits - np.max(logits, axis=1, keepdims=True)
    exp = np.exp(shifted)
    return exp / np.sum(exp, axis=1, keepdims=True)


class ONNXVerifier:
    """Nạp model ONNX + tokenizer + threshold config một lần, tái sử dụng cho
    mọi lần gọi `predict`/`predict_batch` (session không được tạo lại mỗi lần)."""

    def __init__(
        self,
        model_path: str | Path,
        tokenizer_path: str | Path,
        threshold_config_path: str | Path,
    ) -> None:
        self.model_path = Path(model_path)
        self.tokenizer_path = Path(tokenizer_path)
        self.threshold_config_path = Path(threshold_config_path)

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Không tìm thấy model ONNX tại {self.model_path}. "
                "Xem weights/README.md để biết cách tải model."
            )

        session_options = ort.SessionOptions()
        session_options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        self._session = ort.InferenceSession(
            str(self.model_path), sess_options=session_options
        )

        self._tokenizer = AutoTokenizer.from_pretrained(str(self.tokenizer_path))

        with open(self.threshold_config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
        self._thresholds: dict[str, float] = config["thresholds"]
        self._uncertain_zones: dict[str, list[float]] = config["uncertain_zones"]

    def _is_uncertain(self, language: str, confidence: float) -> bool:
        low, high = self._uncertain_zones[language]
        return low <= confidence <= high

    def _run_session(self, encodings: dict[str, np.ndarray]) -> np.ndarray:
        outputs = self._session.run(
            None,
            {
                "input_ids": encodings["input_ids"].astype(np.int64),
                "attention_mask": encodings["attention_mask"].astype(np.int64),
            },
        )
        logits = outputs[0]
        probs = _softmax(logits)
        return probs[:, 1]

    def _classify(self, language: str, confidence: float) -> VerifierResult:
        threshold = self._thresholds[language]
        label = 1 if confidence >= threshold else 0
        status = "UNCERTAIN_NEEDS_REVIEW" if self._is_uncertain(language, confidence) else "OK"
        return VerifierResult(
            ml_verified=True, confidence=confidence, label=label, status=status
        )

    def predict(self, code: str, language: str) -> VerifierResult:
        """Xác minh một candidate sink duy nhất.

        Ngôn ngữ ngoài SUPPORTED_ML_LANGUAGES không được đưa qua model —
        trả về ngay ml_verified=False, không raise lỗi.
        """
        from vulneracheck.verifier import SUPPORTED_ML_LANGUAGES

        language = _normalize_language(language)
        if language not in SUPPORTED_ML_LANGUAGES:
            return VerifierResult(
                ml_verified=False, confidence=None, label=None, status="ML_NOT_SUPPORTED"
            )

        encodings = self._tokenizer(
            code,
            truncation=True,
            max_length=MAX_SEQUENCE_LENGTH,
            return_tensors="np",
        )
        confidence = float(self._run_session(encodings)[0])
        return self._classify(language, confidence)

    def predict_batch(self, items: list[tuple[str, str]]) -> list[VerifierResult]:
        """Xác minh nhiều candidate sink cùng lúc bằng một lần chạy ONNX
        session (dynamic padding theo batch, không pad cứng 512).

        items: danh sách (code, language).
        Trả về danh sách VerifierResult theo đúng thứ tự items đầu vào.
        """
        from vulneracheck.verifier import SUPPORTED_ML_LANGUAGES

        results: list[VerifierResult | None] = [None] * len(items)
        supported_indices: list[int] = []
        supported_codes: list[str] = []
        supported_languages: list[str] = []

        for i, (code, language) in enumerate(items):
            language = _normalize_language(language)
            if language not in SUPPORTED_ML_LANGUAGES:
                results[i] = VerifierResult(
                    ml_verified=False, confidence=None, label=None, status="ML_NOT_SUPPORTED"
                )
            else:
                supported_indices.append(i)
                supported_codes.append(code)
                supported_languages.append(language)

        if supported_codes:
            encodings = self._tokenizer(
                supported_codes,
                truncation=True,
                max_length=MAX_SEQUENCE_LENGTH,
                padding=True,
                return_tensors="np",
            )
            confidences = self._run_session(encodings)
            for i, language, confidence in zip(
                supported_indices, supported_languages, confidences
            ):
                results[i] = self._classify(language, float(confidence))

        return results  # type: ignore[return-value]
