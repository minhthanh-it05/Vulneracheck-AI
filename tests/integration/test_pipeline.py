"""
Integration test cho vulneracheck.pipeline — chạy cascade 3 lớp end-to-end
(secrets -> parsers -> verifier -> reporting) trên toàn bộ thư mục samples/.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulneracheck.pipeline import PipelineConfig, PipelineResult, run_pipeline

SAMPLES_ROOT = Path(__file__).resolve().parent.parent.parent / "samples"


@pytest.fixture
def pipeline_config(tmp_path: Path) -> PipelineConfig:
    return PipelineConfig(
        target_path=SAMPLES_ROOT,
        threshold=0.85,
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


def test_run_pipeline_not_implemented_yet(pipeline_config: PipelineConfig) -> None:
    # TODO: khi các layer được implement đầy đủ, thay assertion này bằng
    # kiểm tra PipelineResult.report chứa đúng finding mong đợi.
    with pytest.raises(NotImplementedError):
        run_pipeline(pipeline_config)
