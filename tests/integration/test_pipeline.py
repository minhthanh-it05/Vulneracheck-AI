"""
Integration test cho vulneracheck.pipeline — chạy cascade 4 bước end-to-end
(secrets -> parsers -> verifier -> reporting) trên toàn bộ thư mục samples/.

Test gọi model ONNX thật bị skip tự động nếu weights/ chưa có model.onnx
(vd. trong CI chưa tải weights) — xem `requires_model`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulneracheck.pipeline import PipelineConfig, PipelineResult, run_pipeline
from vulneracheck.verifier import DEFAULT_MODEL_PATH

SAMPLES_ROOT = Path(__file__).resolve().parent.parent.parent / "samples"

requires_model = pytest.mark.skipif(
    not DEFAULT_MODEL_PATH.exists(),
    reason=f"Model ONNX chưa có tại {DEFAULT_MODEL_PATH} — bỏ qua test gọi pipeline thật.",
)


@pytest.fixture
def pipeline_config(tmp_path: Path) -> PipelineConfig:
    return PipelineConfig(
        target_path=SAMPLES_ROOT,
        output_path=tmp_path / "report.sarif.json",
    )


def test_import_module() -> None:
    assert run_pipeline is not None
    assert PipelineConfig is not None
    assert PipelineResult is not None


def test_samples_root_exists() -> None:
    assert SAMPLES_ROOT.exists()
    assert (SAMPLES_ROOT / "vulnerable").exists()
    assert (SAMPLES_ROOT / "safe").exists()


@requires_model
def test_run_pipeline_end_to_end_on_samples(pipeline_config: PipelineConfig) -> None:
    result = run_pipeline(pipeline_config)

    # Layer 2 phải tìm được candidate sink từ ít nhất vài file mẫu đã biết.
    assert len(result.candidate_sinks) > 0

    # Layer 1 phải bắt được secret cố ý hardcode trong samples/vulnerable/python.
    assert len(result.secret_findings) > 0
    assert any(f.rule_id == "aws-access-key-id" for f in result.secret_findings)

    # Layer 3 phải trả về đúng 1 VerifierResult cho mỗi CandidateSink.
    assert len(result.verified_findings) == len(result.candidate_sinks)
    for vr in result.verified_findings:
        assert vr.status in ("ML_NOT_SUPPORTED", "OK", "UNCERTAIN_NEEDS_REVIEW")
        if vr.ml_verified:
            assert vr.confidence is not None
            assert 0.0 <= vr.confidence <= 1.0
            assert vr.label in (0, 1)
        else:
            assert vr.confidence is None
            assert vr.label is None

    assert result.report is not None
    assert pipeline_config.output_path.exists()


@requires_model
def test_sarif_output_is_valid_and_well_formed(pipeline_config: PipelineConfig) -> None:
    run_pipeline(pipeline_config)

    sarif = json.loads(pipeline_config.output_path.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]
    assert "tool" in run
    assert "driver" in run["tool"]
    assert "results" in run

    for res in run["results"]:
        assert res["level"] in ("error", "warning", "note")
        assert "ruleId" in res
        assert "message" in res
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] > 0


@requires_model
def test_sarif_output_never_contains_raw_secret(pipeline_config: PipelineConfig) -> None:
    # samples/vulnerable/python/command_injection.py hardcode
    # API_KEY = "AKIAIOSFODNN7EXAMPLE" một cách cố ý (fixture, không phải leak
    # thật). Đảm bảo giá trị nguyên văn không lọt vào SARIF output — chỉ được
    # xuất hiện dạng đã redact.
    run_pipeline(pipeline_config)

    sarif_text = pipeline_config.output_path.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in sarif_text
    assert "AKIA****" in sarif_text
