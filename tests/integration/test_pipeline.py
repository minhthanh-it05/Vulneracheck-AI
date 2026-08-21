"""
Integration test for vulneracheck.pipeline — runs the 4-step cascade
end-to-end (secrets -> parsers -> verifier -> reporting) over the whole
samples/ directory.

Tests that call the real ONNX model are automatically skipped if weights/
doesn't have model.onnx yet (e.g. in CI before weights are downloaded) —
see `requires_model`.
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
    reason=f"ONNX model not found at {DEFAULT_MODEL_PATH} — skipping tests that call the real pipeline.",
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

    # Layer 2 must find candidate sinks from at least a few known sample files.
    assert len(result.candidate_sinks) > 0

    # Layer 1 must catch the secret deliberately hardcoded in samples/vulnerable/python.
    assert len(result.secret_findings) > 0
    assert any(f.rule_id == "aws-access-key-id" for f in result.secret_findings)

    # Layer 3 must return exactly 1 VerifierResult per CandidateSink.
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
    # samples/vulnerable/python/command_injection.py deliberately hardcodes
    # API_KEY = "AKIAIOSFODNN7EXAMPLE" (a fixture, not a real leak). Make
    # sure the raw value never leaks into the SARIF output — only the
    # redacted form should appear.
    run_pipeline(pipeline_config)

    sarif_text = pipeline_config.output_path.read_text(encoding="utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in sarif_text
    assert "AKIA****" in sarif_text
