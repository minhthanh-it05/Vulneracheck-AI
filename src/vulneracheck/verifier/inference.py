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

# Batch quá lớn trong 1 lần session.run() bị chậm SIÊU tuyến tính trên CPU:
# padding là dynamic THEO ITEM DÀI NHẤT TRONG BATCH, nên batch càng lớn càng
# dễ "dính" phải ít nhất 1 snippet dài (candidate sink giờ mang cả function
# bao quanh, có thể dài hàng chục nghìn ký tự trước khi truncate) và kéo
# TOÀN BỘ batch bị pad theo độ dài đó. Đã đo thực nghiệm trên repo thật
# (moonlight-common-c, 229 candidate): N=10 ~5.4s, N=30 ~13.5s, N=60 ~26.6s
# (~0.45s/candidate, tuyến tính) nhưng N=200+ không hoàn thành sau nhiều phút.
# Chunk cố định theo MAX_BATCH_SIZE để chặn tensor phồng to bất thường,
# đổi lại nhiều lần gọi session.run() hơn (vẫn là batch thật mỗi lần, không
# phải loop predict() từng candidate).
MAX_BATCH_SIZE = 32

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

    def predict_batch(
        self, items: list[tuple[str, str]], batch_size: int = MAX_BATCH_SIZE
    ) -> list[VerifierResult]:
        """Xác minh nhiều candidate sink cùng lúc, chia thành các batch con
        cố định kích thước `batch_size` (mỗi batch con vẫn là 1 lần gọi
        session.run() thật — không loop predict() từng candidate). Xem
        MAX_BATCH_SIZE để biết lý do cần chunk thay vì gộp tất cả vào 1 batch.

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

        for start in range(0, len(supported_codes), batch_size):
            chunk_indices = supported_indices[start : start + batch_size]
            chunk_codes = supported_codes[start : start + batch_size]
            chunk_languages = supported_languages[start : start + batch_size]

            encodings = self._tokenizer(
                chunk_codes,
                truncation=True,
                max_length=MAX_SEQUENCE_LENGTH,
                padding=True,
                return_tensors="np",
            )
            confidences = self._run_session(encodings)
            for i, language, confidence in zip(chunk_indices, chunk_languages, confidences):
                results[i] = self._classify(language, float(confidence))

        return results  # type: ignore[return-value]
