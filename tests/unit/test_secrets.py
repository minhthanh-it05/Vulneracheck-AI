"""
Unit tests cho vulneracheck.secrets (Layer 1: regex/pattern matching).

Fixture: dùng file mẫu trong samples/vulnerable và samples/safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulneracheck.secrets import scan_file, scan_text

SAMPLES_ROOT = Path(__file__).resolve().parent.parent.parent / "samples"
VULNERABLE_PY = SAMPLES_ROOT / "vulnerable" / "python" / "command_injection.py"
SAFE_PY = SAMPLES_ROOT / "safe" / "python" / "command_runner.py"


@pytest.fixture
def vulnerable_sample_path() -> Path:
    return VULNERABLE_PY


@pytest.fixture
def safe_sample_path() -> Path:
    return SAFE_PY


def test_import_module() -> None:
    assert scan_file is not None
    assert scan_text is not None


def test_load_vulnerable_sample(vulnerable_sample_path: Path) -> None:
    assert vulnerable_sample_path.exists()
    content = vulnerable_sample_path.read_text(encoding="utf-8")
    assert len(content) > 0


def test_load_safe_sample(safe_sample_path: Path) -> None:
    assert safe_sample_path.exists()
    content = safe_sample_path.read_text(encoding="utf-8")
    assert len(content) > 0


def test_scan_vulnerable_sample_runs(vulnerable_sample_path: Path) -> None:
    # TODO: assert rằng finding hardcoded API key được phát hiện đúng.
    findings = scan_file(str(vulnerable_sample_path))
    assert isinstance(findings, list)


def test_scan_safe_sample_runs(safe_sample_path: Path) -> None:
    # TODO: assert rằng không có false positive trên sample an toàn.
    findings = scan_file(str(safe_sample_path))
    assert isinstance(findings, list)
