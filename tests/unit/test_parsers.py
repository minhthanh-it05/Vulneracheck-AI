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
VULNERABLE_C = SAMPLES_ROOT / "vulnerable" / "c" / "buffer_overflow.c"
SAFE_C = SAMPLES_ROOT / "safe" / "c" / "bounded_copy.c"
VULNERABLE_CPP = SAMPLES_ROOT / "vulnerable" / "cpp" / "buffer_overflow.cpp"
SAFE_CPP = SAMPLES_ROOT / "safe" / "cpp" / "bounded_copy.cpp"


@pytest.fixture
def engine() -> TreeSitterEngine:
    return TreeSitterEngine()


@pytest.fixture(
    params=[
        VULNERABLE_PY,
        SAFE_PY,
        VULNERABLE_JAVA,
        SAFE_JAVA,
        VULNERABLE_C,
        SAFE_C,
        VULNERABLE_CPP,
        SAFE_CPP,
    ]
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


@pytest.mark.parametrize(
    "extension",
    [".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh"],
)
def test_c_cpp_rule_wiring_loads_query(engine: TreeSitterEngine, extension: str) -> None:
    """Rule .scm cho C/C++ đã được wiring đúng trong LANGUAGE_RULE_MAP —
    không còn raise ValueError như trước khi rules/c, rules/cpp có nội dung.
    Chưa test parse_file() thật vì TreeSitterEngine chưa tích hợp grammar."""
    query_text = engine._load_query(extension)
    assert len(query_text) > 0
    assert "@sink.name" in query_text
