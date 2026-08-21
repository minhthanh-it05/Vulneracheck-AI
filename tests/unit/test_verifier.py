"""
Unit tests for vulneracheck.verifier (Layer 3: GraphCodeBERT ONNX classifier).

Fixtures: use sample files in samples/vulnerable and samples/safe.

Tests that call the real model are automatically skipped if weights/
doesn't have model.onnx yet (e.g. in CI before weights are downloaded) —
see `requires_model`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulneracheck.verifier import (
    DEFAULT_MODEL_PATH,
    DEFAULT_THRESHOLD_CONFIG_PATH,
    DEFAULT_TOKENIZER_PATH,
    SUPPORTED_ML_LANGUAGES,
    ONNXVerifier,
)
from vulneracheck.verifier.types import VerifierResult

SAMPLES_ROOT = Path(__file__).resolve().parent.parent.parent / "samples"
VULNERABLE_JAVA = SAMPLES_ROOT / "vulnerable" / "java" / "SqlInjection.java"
SAFE_JAVA = SAMPLES_ROOT / "safe" / "java" / "UserQuery.java"
VULNERABLE_PY = SAMPLES_ROOT / "vulnerable" / "python" / "command_injection.py"

requires_model = pytest.mark.skipif(
    not DEFAULT_MODEL_PATH.exists(),
    reason=f"ONNX model not found at {DEFAULT_MODEL_PATH} — skipping tests that call the real model.",
)


@pytest.fixture(scope="module")
def verifier() -> ONNXVerifier:
    return ONNXVerifier(
        model_path=DEFAULT_MODEL_PATH,
        tokenizer_path=DEFAULT_TOKENIZER_PATH,
        threshold_config_path=DEFAULT_THRESHOLD_CONFIG_PATH,
    )


def test_import_module() -> None:
    assert ONNXVerifier is not None
    assert VerifierResult is not None


def test_supported_ml_languages() -> None:
    assert SUPPORTED_ML_LANGUAGES == ["c", "cpp", "java"]


# --- Unsupported language branch: does not raise, returns ml_verified=False ---


def test_predict_unsupported_language_does_not_call_model(verifier: ONNXVerifier) -> None:
    code = VULNERABLE_PY.read_text(encoding="utf-8")
    result = verifier.predict(code, language="python")

    assert result.ml_verified is False
    assert result.confidence is None
    assert result.label is None
    assert result.status == "ML_NOT_SUPPORTED"


def test_predict_batch_unsupported_language(verifier: ONNXVerifier) -> None:
    code = VULNERABLE_PY.read_text(encoding="utf-8")
    results = verifier.predict_batch([(code, "python"), (code, "javascript")])

    assert len(results) == 2
    assert all(r.ml_verified is False and r.status == "ML_NOT_SUPPORTED" for r in results)


# --- Supported language branch: calls the real model on a sample from samples/ ---


@requires_model
def test_predict_supported_language_runs_real_model(verifier: ONNXVerifier) -> None:
    code = VULNERABLE_JAVA.read_text(encoding="utf-8")
    result = verifier.predict(code, language="java")

    assert result.ml_verified is True
    assert isinstance(result.confidence, float)
    assert 0.0 <= result.confidence <= 1.0
    assert result.label in (0, 1)
    assert result.status in ("OK", "UNCERTAIN_NEEDS_REVIEW")


@requires_model
def test_predict_batch_mixed_languages(verifier: ONNXVerifier) -> None:
    vulnerable_code = VULNERABLE_JAVA.read_text(encoding="utf-8")
    safe_code = SAFE_JAVA.read_text(encoding="utf-8")
    unsupported_code = VULNERABLE_PY.read_text(encoding="utf-8")

    results = verifier.predict_batch(
        [
            (vulnerable_code, "java"),
            (safe_code, "java"),
            (unsupported_code, "python"),
        ]
    )

    assert len(results) == 3
    assert results[0].ml_verified is True
    assert results[1].ml_verified is True
    assert results[2].ml_verified is False
    assert results[2].status == "ML_NOT_SUPPORTED"
