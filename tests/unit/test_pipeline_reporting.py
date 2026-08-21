"""
Unit tests for vulneracheck.pipeline.run_reporting_layer — specifically the
decision to mitigate the systematic false positive issue for the C/C++
buffer/format sink group (see docs/model_card.md and
LOW_CONFIDENCE_CWE_CATEGORIES in reporting/).

Tests use hand-built CandidateSink/VerifierResult (no real ONNX model
needed) to check the pure severity-decision logic, running fast.
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
    # strncpy is in the memory-unsafe group (CWE-119/416/476) — confirmed to
    # have a systematic FP issue. Even though the verifier returns very high
    # confidence (0.97) and label=1, the finding MUST come out as
    # severity="warning", not "error".
    candidate = _candidate("strncpy", cwe=["CWE-119", "CWE-416", "CWE-476"])
    result = _verified_result(confidence=0.97, label=1, status="OK")

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == "warning"
    assert finding.extra_properties["low_confidence_category"] is True
    assert "note" in finding.extra_properties
    # The real confidence number is NOT stripped/rounded.
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
    # delete/delete[] SHARES CWE-416/CWE-476 codes with the memory-unsafe
    # group in the .scm rule, but does NOT have the same false positive
    # issue (on the contrary, it improved well: 0.66 -> 0.98). Must be
    # explicitly excluded, must not be caught just because it shares a CWE code.
    candidate = _candidate("delete", cwe=["CWE-416", "CWE-476"], file_path="app.cpp")
    result = _verified_result(confidence=0.98, label=1, status="OK")

    report = run_reporting_layer([], [(candidate, result)], tmp_path / "report.sarif.json")

    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.severity == "error"
    assert "low_confidence_category" not in finding.extra_properties


def test_command_injection_sink_not_affected(tmp_path: Path) -> None:
    # system/exec (CWE-78, CWE-88) is not in LOW_CONFIDENCE_CWE_CATEGORIES —
    # the verifier performs well on this group, no mitigation needed.
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
