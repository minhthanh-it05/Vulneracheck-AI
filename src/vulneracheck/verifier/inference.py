"""
inference.py: The real implementation of Layer 3 — GraphCodeBERT
(RoBERTa-based) running through ONNX Runtime to classify each candidate
sink as safe/vulnerable, with a per-language threshold and uncertain-zone.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import onnxruntime as ort
from transformers import AutoTokenizer

from vulneracheck.verifier.types import VerifierResult

MAX_SEQUENCE_LENGTH = 512

# A batch that's too large in a single session.run() call becomes SUPER
# linear-slow on CPU: padding is dynamic BASED ON THE LONGEST ITEM IN THE
# BATCH, so the larger the batch, the more likely it "catches" at least one
# long snippet (a candidate sink now carries its whole enclosing function,
# which can be tens of thousands of characters before truncation) and drags
# the ENTIRE batch to be padded to that length. Measured empirically on a
# real repo (moonlight-common-c, 229 candidates): N=10 ~5.4s, N=30 ~13.5s,
# N=60 ~26.6s (~0.45s/candidate, linear) but N=200+ did not complete after
# several minutes. Chunk with a fixed MAX_BATCH_SIZE to cap abnormal tensor
# growth, at the cost of more session.run() calls (each is still a real
# batch, not a predict() loop per candidate).
MAX_BATCH_SIZE = 32

# Common language aliases -> canonical name used in threshold_config.json
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
    """Loads the ONNX model + tokenizer + threshold config once, reused for
    every `predict`/`predict_batch` call (the session is not recreated each time)."""

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
                f"ONNX model not found at {self.model_path}. "
                "See weights/README.md for how to download the model."
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
        """Verify a single candidate sink.

        A language outside SUPPORTED_ML_LANGUAGES is not passed through the
        model — returns ml_verified=False immediately, without raising.
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
        """Verify multiple candidate sinks at once, split into fixed-size
        sub-batches of `batch_size` (each sub-batch is still one real
        session.run() call — not a predict() loop per candidate). See
        MAX_BATCH_SIZE for why chunking is needed instead of merging
        everything into one giant batch.

        items: list of (code, language).
        Returns a list of VerifierResult in the same order as the input items.
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
