"""
Unit tests cho vulneracheck.parsers (Layer 2: Tree-sitter AST parser, high-recall).

Fixture: dùng file mẫu trong samples/vulnerable và samples/safe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulneracheck.parsers import CandidateSink, TreeSitterEngine

SAMPLES_ROOT = Path(__file__).resolve().parent.parent.parent / "samples"
VULNERABLE_PY = SAMPLES_ROOT / "vulnerable" / "python" / "command_injection.py"
SAFE_PY = SAMPLES_ROOT / "safe" / "python" / "command_runner.py"
VULNERABLE_JAVA = SAMPLES_ROOT / "vulnerable" / "java" / "SqlInjection.java"
SAFE_JAVA = SAMPLES_ROOT / "safe" / "java" / "UserQuery.java"


@pytest.fixture
def engine() -> TreeSitterEngine:
    return TreeSitterEngine()


@pytest.fixture(
    params=[VULNERABLE_PY, SAFE_PY, VULNERABLE_JAVA, SAFE_JAVA]
)
def sample_path(request: pytest.FixtureRequest) -> Path:
    return request.param


def test_import_module() -> None:
    assert CandidateSink is not None
    assert TreeSitterEngine is not None


def test_load_sample(sample_path: Path) -> None:
    assert sample_path.exists()
    content = sample_path.read_text(encoding="utf-8")
    assert len(content) > 0


def test_parse_file_not_implemented_yet(engine: TreeSitterEngine, sample_path: Path) -> None:
    # TODO: khi tích hợp Tree-sitter grammar thật, thay assertion này bằng
    # kiểm tra danh sách CandidateSink trả về đúng theo rule .scm.
    with pytest.raises(NotImplementedError):
        engine.parse_file(str(sample_path))
