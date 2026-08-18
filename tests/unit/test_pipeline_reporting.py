"""
Unit tests cho vulneracheck.pipeline.run_reporting_layer — đặc biệt là quyết
định giảm thiểu false positive hệ thống cho nhóm sink buffer/format C/C++
(xem docs/model_card.md và LOW_CONFIDENCE_CWE_CATEGORIES trong reporting/).

Test dùng CandidateSink/VerifierResult dựng tay (không cần model ONNX thật)
để kiểm tra logic quyết định severity thuần tuý, chạy nhanh.
"""

from __future__ import annotations

from pathlib import Path

from vulneracheck.parsers import CandidateSink
from vulneracheck.pipeline import run_reporting_layer
from vulneracheck.verifier import VerifierResult


def _candidate(sink_name: str, cwe: list[str], file_path: str = "app.c") -> CandidateSink:
    return CandidateSink(
        file_path=file_path,
        line=10,
        column=5,
        sink_name=sink_name,
        snippet=f"{sink_name}(...);",
        cwe=cwe,
    )


def _verified_result(confidence: float, label: int, status: str = "OK") -> VerifierResult:
    return VerifierResult(ml_verified=True, confidence=confidence, label=label, status=status)


def test_low_confidence_cwe_category_forces_warning_despite_high_confidence(
    tmp_path: Path,
) -> None:
    # strncpy thuộc nhóm memory-unsafe (CWE-119/416/476) — đã xác nhận FP hệ
    # thống. Dù verifier trả confidence rất cao (0.97) và label=1, finding
    # PHẢI ra severity="warning", không phải "error".
    candidate = _candidate("strncpy", cwe=["CWE-119", "CWE-416", "CWE-476"])
    result = _verified_result(confidence=0.97, label=1, status="OK")

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == "warning"
    assert finding.extra_properties["low_confidence_category"] is True
    assert "note" in finding.extra_properties
    # Confidence số thật KHÔNG bị xoá/làm tròn.
    assert finding.confidence == 0.97
    serialized = report.to_dict()
    assert serialized["runs"][0]["results"][0]["properties"]["confidence"] == 0.97
    assert serialized["runs"][0]["results"][0]["level"] == "warning"


def test_low_confidence_category_also_applies_to_format_string_group(tmp_path: Path) -> None:
    candidate = _candidate("snprintf", cwe=["CWE-134"])
    result = _verified_result(confidence=0.85, label=1, status="OK")

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert report.findings[0].severity == "warning"
    assert report.findings[0].extra_properties["low_confidence_category"] is True


def test_delete_sink_not_affected_despite_sharing_cwe_codes(tmp_path: Path) -> None:
    # delete/delete[] dùng CHUNG mã CWE-416/CWE-476 với nhóm memory-unsafe
    # trong rule .scm, nhưng KHÔNG bị vấn đề false positive tương tự (ngược
    # lại, cải thiện tốt: 0.66 -> 0.98). Phải loại trừ tường minh, không được
    # bị bắt nhầm chỉ vì trùng mã CWE.
    candidate = _candidate("delete", cwe=["CWE-416", "CWE-476"], file_path="app.cpp")
    result = _verified_result(confidence=0.98, label=1, status="OK")

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == "error"
    assert "low_confidence_category" not in finding.extra_properties


def test_command_injection_sink_not_affected(tmp_path: Path) -> None:
    # system/exec (CWE-78, CWE-88) không nằm trong LOW_CONFIDENCE_CWE_CATEGORIES
    # — verifier cải thiện tốt cho nhóm này, không cần giảm thiểu.
    candidate = _candidate("system", cwe=["CWE-78", "CWE-88"], file_path="app.cpp")
    result = _verified_result(confidence=0.72, label=1, status="OK")

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert report.findings[0].severity == "error"
    assert "low_confidence_category" not in report.findings[0].extra_properties


def test_low_confidence_category_applies_to_uncertain_status_too(tmp_path: Path) -> None:
    candidate = _candidate("memcpy", cwe=["CWE-119", "CWE-416", "CWE-476"])
    result = _verified_result(confidence=0.65, label=1, status="UNCERTAIN_NEEDS_REVIEW")

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert report.findings[0].severity == "warning"
    assert report.findings[0].extra_properties["low_confidence_category"] is True
    assert report.findings[0].extra_properties["status"] == "UNCERTAIN_NEEDS_REVIEW"
