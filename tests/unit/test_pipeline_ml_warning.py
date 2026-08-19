"""
Unit tests cho cảnh báo tổng hợp "candidate chưa qua xác minh AI" — xem
vulneracheck.pipeline.build_ml_unsupported_warning và
ML_NOT_SUPPORTED_NOTE trong reporting/__init__.py.

Ngữ cảnh: candidate từ ngôn ngữ ngoài SUPPORTED_ML_LANGUAGES (hiện tại:
Python — Layer 2 có rule .scm riêng nhưng Layer 3 thì không) đi qua Layer 2
bình thường nhưng verifier trả ml_verified=False. Không có cảnh báo rõ ràng
thì người dùng dễ đánh đồng độ tin cậy với finding C/C++/Java đã qua Layer 3.

Test dùng CandidateSink/VerifierResult dựng tay (không cần model ONNX thật),
theo đúng convention của test_pipeline_reporting.py.
"""

from __future__ import annotations

from pathlib import Path

from vulneracheck.parsers import CandidateSink
from vulneracheck.pipeline import build_ml_unsupported_warning, run_reporting_layer
from vulneracheck.reporting import ML_NOT_SUPPORTED_NOTE
from vulneracheck.verifier import VerifierResult


def _candidate(sink_name: str, file_path: str, cwe: list[str] | None = None) -> CandidateSink:
    return CandidateSink(
        file_path=file_path,
        line=10,
        column=5,
        sink_name=sink_name,
        snippet=f"{sink_name}(...)",
        cwe=cwe or [],
    )


def _ml_verified_result(confidence: float, label: int, status: str = "OK") -> VerifierResult:
    return VerifierResult(ml_verified=True, confidence=confidence, label=label, status=status)


def _ml_not_supported_result() -> VerifierResult:
    return VerifierResult(ml_verified=False, confidence=None, label=None, status="ML_NOT_SUPPORTED")


def test_no_warning_when_all_candidates_are_c_cpp_java() -> None:
    verified_candidates = [
        (_candidate("strcpy", "app.c"), _ml_verified_result(0.9, 1)),
        (_candidate("memcpy", "app.cpp"), _ml_verified_result(0.3, 0)),
        (_candidate("executeQuery", "App.java"), _ml_verified_result(0.6, 1, "UNCERTAIN_NEEDS_REVIEW")),
    ]

    assert build_ml_unsupported_warning(verified_candidates) is None


def test_no_warning_when_no_candidates_at_all() -> None:
    assert build_ml_unsupported_warning([]) is None


def test_warning_present_when_unsupported_language_candidate_exists() -> None:
    verified_candidates = [
        (_candidate("strcpy", "app.c"), _ml_verified_result(0.9, 1)),
        (_candidate("os.system", "script.py"), _ml_not_supported_result()),
    ]

    warning = build_ml_unsupported_warning(verified_candidates)

    assert warning is not None
    assert warning.startswith("⚠️")
    assert "1 candidate" in warning
    assert "Python" in warning
    assert "C/C++/Java" in warning


def test_warning_counts_only_unsupported_candidates_and_lists_unique_languages() -> None:
    verified_candidates = [
        (_candidate("strcpy", "app.c"), _ml_verified_result(0.9, 1)),
        (_candidate("os.system", "a.py"), _ml_not_supported_result()),
        (_candidate("subprocess.call", "b.py"), _ml_not_supported_result()),
        (_candidate("eval", "c.py"), _ml_not_supported_result()),
    ]

    warning = build_ml_unsupported_warning(verified_candidates)

    assert warning is not None
    # 3 candidate Python không hỗ trợ, KHÔNG tính candidate C đã ml_verified=True.
    assert "3 candidate" in warning
    # Chỉ 1 ngôn ngữ (Python) dù có 3 candidate — không lặp lại tên ngôn ngữ.
    assert warning.count("Python") == 1


def test_ml_not_supported_finding_has_explanatory_note_in_sarif(tmp_path: Path) -> None:
    candidate = _candidate("os.system", "script.py")
    result = _ml_not_supported_result()

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == "warning"
    assert finding.extra_properties["ml_verified"] is False
    assert finding.extra_properties["note"] == ML_NOT_SUPPORTED_NOTE

    serialized = report.to_dict()
    result_properties = serialized["runs"][0]["results"][0]["properties"]
    assert result_properties["ml_verified"] is False
    assert result_properties["note"] == ML_NOT_SUPPORTED_NOTE
