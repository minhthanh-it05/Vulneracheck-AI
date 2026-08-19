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
QUALIFIED_CALL_VULNERABLE_CPP = (
    SAMPLES_ROOT / "vulnerable" / "cpp" / "qualified_call_vulnerable.cpp"
)


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
        QUALIFIED_CALL_VULNERABLE_CPP,
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


@pytest.mark.parametrize(
    "extension",
    [".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh", ".java", ".py"],
)
def test_rule_wiring_loads_query(engine: TreeSitterEngine, extension: str) -> None:
    """Rule .scm cho mọi ngôn ngữ đã được wiring đúng trong LANGUAGE_RULE_MAP."""
    query_text = engine._load_query(extension)
    assert len(query_text) > 0
    assert "@sink.name" in query_text


@pytest.mark.parametrize(
    "sample,expected_sinks",
    [
        (VULNERABLE_PY, {"popen", "call"}),
        (SAFE_PY, {"run"}),
        (VULNERABLE_JAVA, {"executeQuery", "exec"}),
        (SAFE_JAVA, {"executeQuery"}),
        (VULNERABLE_C, {"strcpy", "printf", "gets"}),
        (SAFE_C, {"strncpy", "printf"}),
        (VULNERABLE_CPP, {"strcpy", "system", "delete"}),
        (SAFE_CPP, {"strncpy"}),
        (QUALIFIED_CALL_VULNERABLE_CPP, {"strcpy", "sprintf", "printf"}),
    ],
)
def test_parse_file_finds_expected_sinks(
    engine: TreeSitterEngine, sample: Path, expected_sinks: set[str]
) -> None:
    candidates = engine.parse_file(str(sample))
    assert len(candidates) > 0

    found_names = {c.sink_name for c in candidates}
    assert expected_sinks.issubset(found_names)

    for candidate in candidates:
        assert candidate.file_path == str(sample)
        assert candidate.line > 0
        assert candidate.column > 0
        assert candidate.snippet != ""


def test_parse_file_extracts_cwe_tags_for_known_pattern(engine: TreeSitterEngine) -> None:
    candidates = engine.parse_file(str(VULNERABLE_C))
    strcpy_candidates = [c for c in candidates if c.sink_name == "strcpy"]
    assert strcpy_candidates
    assert "CWE-120" in strcpy_candidates[0].cwe


def test_parse_file_unsupported_extension_returns_empty_list(
    engine: TreeSitterEngine, tmp_path: Path
) -> None:
    # Ngoài phạm vi hỗ trợ (vd. .txt) -> list rỗng, KHÔNG raise lỗi.
    unsupported = tmp_path / "notes.txt"
    unsupported.write_text("just some plain text, not source code", encoding="utf-8")
    assert engine.parse_file(str(unsupported)) == []


@pytest.mark.parametrize(
    "sample,sink_name,expected_signature",
    [
        (VULNERABLE_C, "strcpy", "void copy_input"),
        (SAFE_C, "strncpy", "void copy_input"),
        (VULNERABLE_CPP, "strcpy", "void copy_input"),
        (SAFE_CPP, "strncpy", "void copy_input"),
        (VULNERABLE_JAVA, "exec", "public void runCommand"),
        (VULNERABLE_PY, "popen", "def run_ping"),
    ],
)
def test_parse_file_snippet_is_full_enclosing_function(
    engine: TreeSitterEngine, sample: Path, sink_name: str, expected_signature: str
) -> None:
    # snippet phải là TOÀN BỘ function bao quanh sink (nhiều dòng, chứa chữ
    # ký hàm), không chỉ 1 dòng chứa sink — giảm distribution shift so với
    # dữ liệu function-level lúc train verifier.
    candidates = engine.parse_file(str(sample))
    match = next(c for c in candidates if c.sink_name == sink_name)
    assert expected_signature in match.snippet
    assert match.snippet.count("\n") > 0


def test_parse_file_detects_namespace_qualified_calls(engine: TreeSitterEngine) -> None:
    # cpp_sinks.scm phải bắt được cả dạng gọi qualified (std::strcpy,
    # std::sprintf, std::printf), không chỉ dạng gọi trực tiếp — code C++
    # hiện đại rất hay gọi tường minh qua std::.
    candidates = engine.parse_file(str(QUALIFIED_CALL_VULNERABLE_CPP))

    found_names = {c.sink_name for c in candidates}
    assert {"strcpy", "sprintf", "printf"}.issubset(found_names)

    strcpy_candidates = [c for c in candidates if c.sink_name == "strcpy"]
    assert strcpy_candidates
    assert "CWE-120" in strcpy_candidates[0].cwe
    assert strcpy_candidates[0].file_path == str(QUALIFIED_CALL_VULNERABLE_CPP)
    assert strcpy_candidates[0].line > 0

    sprintf_candidates = [c for c in candidates if c.sink_name == "sprintf"]
    assert sprintf_candidates
    assert "CWE-120" in sprintf_candidates[0].cwe


def test_parse_file_detects_wrapper_function_names(
    engine: TreeSitterEngine, tmp_path: Path
) -> None:
    # Predicate #match? phải bắt được wrapper function tự định nghĩa bọc
    # quanh hàm libc gốc (vd. mpack_memcpy trong mpack thật) — trước khi
    # sửa (^|_)(...)($|_), exact-match "^(...)$" bỏ sót hoàn toàn case này.
    # Case thật: nơi GỌI wrapper (vd. mpack_memcpy(...)), không phải nơi
    # định nghĩa wrapper gọi hàm libc gốc bên trong (case đó @sink.name đã
    # bắt được "memcpy"/"strcpy" từ trước, không phải gap cần sửa).
    wrapper_file = tmp_path / "wrapper.c"
    wrapper_file.write_text(
        "void use_buffer(char *dst, const char *src, size_t n) {\n"
        "    mpack_memcpy(dst, src, n);\n"
        "}\n"
        "void use_string(char *dst, const char *src) {\n"
        "    my_strcpy_wrapper(dst, src);\n"
        "}\n",
        encoding="utf-8",
    )

    candidates = engine.parse_file(str(wrapper_file))
    found_names = {c.sink_name for c in candidates}

    assert "mpack_memcpy" in found_names
    assert "my_strcpy_wrapper" in found_names


def test_parse_file_does_not_match_unrelated_function_names(
    engine: TreeSitterEngine, tmp_path: Path
) -> None:
    # Nới rộng match KHÔNG được match nhầm tên hàm hoàn toàn không liên quan
    # chỉ tình cờ chứa 1 chuỗi con dính liền (không tách bằng underscore).
    unrelated_file = tmp_path / "unrelated.c"
    unrelated_file.write_text(
        "void process_data(void) { calculate_total(); }\n"
        "int mallocator(void) { return 0; }\n"
        "void freetype_init(void) {}\n"
        "void calculate_total(void) {}\n",
        encoding="utf-8",
    )

    candidates = engine.parse_file(str(unrelated_file))
    found_names = {c.sink_name for c in candidates}

    assert found_names == set()


def test_parse_file_detects_camelcase_wrapper_function_names(
    engine: TreeSitterEngine, tmp_path: Path
) -> None:
    # Predicate #match? phải bắt được wrapper function đặt tên kiểu
    # camelCase/PascalCase (không dùng underscore) bên cạnh snake_case đã
    # có từ trước — xem docs/model_card.md mục "Mở rộng bắt wrapper dạng
    # camelCase/PascalCase". "safeStrCpy" cố ý viết hoa CẢ 2 "hump" (Str +
    # Cpy) để xác nhận nhánh camelCase so khớp tên sink không phân biệt
    # hoa/thường, không chỉ riêng dạng "Strcpy" hoa mỗi chữ đầu.
    wrapper_file = tmp_path / "wrapper_camelcase.c"
    wrapper_file.write_text(
        "void use_buffer(char *dst, const char *src, size_t n) {\n"
        "    mpackMemcpy(dst, src, n);\n"
        "}\n"
        "void use_string(char *dst, const char *src) {\n"
        "    safeStrCpy(dst, src);\n"
        "}\n"
        "void use_malloc(size_t n) {\n"
        "    MallocWrapper(n);\n"
        "}\n",
        encoding="utf-8",
    )

    candidates = engine.parse_file(str(wrapper_file))
    found_names = {c.sink_name for c in candidates}

    assert "mpackMemcpy" in found_names
    assert "safeStrCpy" in found_names
    # PascalCase (chính wrapper bắt đầu bằng chữ hoa, không có tiền tố).
    assert "MallocWrapper" in found_names


def test_parse_file_does_not_match_unrelated_camelcase_names(
    engine: TreeSitterEngine, tmp_path: Path
) -> None:
    # Nhánh camelCase mới KHÔNG được match nhầm: (1) tên toàn chữ thường
    # tình cờ chứa chuỗi con dính liền, không có điểm chuyển hoa nào để
    # nhánh camelCase bắt (somestrcpycall); (2) tên chứa đúng các chữ cái
    # nhưng KHÔNG liền mạch thành từ sink gốc (myStructCpy: "Struct" != "Str"
    # nối "cpy"); (3) 2 chữ hoa liền kề kiểu viết tắt, không phải ranh giới
    # từ hợp lệ (XStrcpy).
    unrelated_file = tmp_path / "unrelated_camelcase.c"
    unrelated_file.write_text(
        "void run(void) {\n"
        "    somestrcpycall();\n"
        "    myStructCpy();\n"
        "    XStrcpy();\n"
        "}\n",
        encoding="utf-8",
    )

    candidates = engine.parse_file(str(unrelated_file))
    found_names = {c.sink_name for c in candidates}

    assert found_names == set()


# --- Test hồi quy: bản vá camelCase/PascalCase (2026-08-19) không được làm
# GIẢM số candidate quét được trên samples/ so với trước khi vá. Dựng lại
# rule "trước khi vá" (chỉ có nhánh snake_case, KHÔNG có nhánh camelCase) tại
# chỗ trong 1 rules_dir tạm, không phụ thuộc `git show HEAD:...` — tránh test
# trở nên vô nghĩa sau khi thay đổi này được commit (HEAD lúc đó đã là bản
# MỚI). Token list giữ nguyên giống rules/{c,cpp}/*_sinks.scm hiện tại.

_OLD_BUFFER_TOKENS = "strcpy|strcat|sprintf|vsprintf|gets|scanf|stpcpy|wcscpy|wcscat"
_OLD_MEMORY_TOKENS = "memcpy|memmove|memset|alloca|strncpy|strncat|realloc|free"
_OLD_FORMAT_TOKENS = "printf|fprintf|snprintf|syslog|vfprintf"
_OLD_CMD_TOKENS = (
    "system|popen|exec|execl|execlp|execle|execv|execvp|execve|"
    "ShellExecute[AW]?|CreateProcess[AW]?"
)
_OLD_CMD_TOKENS_QUALIFIED = "system|popen|exec|execl|execlp|execle|execv|execvp|execve"
_OLD_MALLOC_TOKENS = "malloc|calloc"

_C_CPP_EXTENSIONS = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".hh"}


def _snake_case_only_pattern(tokens: str) -> str:
    # Predicate #match? y hệt bản NGAY TRƯỚC bản vá camelCase/PascalCase
    # hiện tại (chỉ bắt snake_case — xem docs/model_card.md mục vá
    # 2026-08-18, trước mục "Mở rộng bắt wrapper dạng camelCase/PascalCase").
    return f"(^|_)({tokens})($|_)"


def _write_pre_camelcase_rules(root: Path) -> Path:
    (root / "c").mkdir(parents=True)
    (root / "cpp").mkdir(parents=True)

    def _call_pattern(tokens: str, qualified: bool = False) -> str:
        function_node = (
            "(qualified_identifier\n    name: (identifier) @sink.name)"
            if qualified
            else "(identifier) @sink.name"
        )
        return (
            "(call_expression\n"
            f"  function: {function_node}\n"
            "  arguments: (argument_list) @sink.args\n"
            f'  (#match? @sink.name "{_snake_case_only_pattern(tokens)}"))\n'
        )

    c_query = "\n".join(
        _call_pattern(tokens)
        for tokens in (
            _OLD_BUFFER_TOKENS,
            _OLD_MEMORY_TOKENS,
            _OLD_FORMAT_TOKENS,
            _OLD_CMD_TOKENS,
            _OLD_MALLOC_TOKENS,
        )
    )
    (root / "c" / "c_sinks.scm").write_text(c_query, encoding="utf-8")

    cpp_query = "\n".join(
        [
            _call_pattern(_OLD_BUFFER_TOKENS),
            _call_pattern(_OLD_BUFFER_TOKENS, qualified=True),
            _call_pattern(_OLD_MEMORY_TOKENS),
            _call_pattern(_OLD_MEMORY_TOKENS, qualified=True),
            '(delete_expression "delete" @sink.name) @sink.args\n',
            _call_pattern(_OLD_FORMAT_TOKENS),
            _call_pattern(_OLD_FORMAT_TOKENS, qualified=True),
            _call_pattern(_OLD_CMD_TOKENS),
            _call_pattern(_OLD_CMD_TOKENS_QUALIFIED, qualified=True),
            _call_pattern(_OLD_MALLOC_TOKENS),
        ]
    )
    (root / "cpp" / "cpp_sinks.scm").write_text(cpp_query, encoding="utf-8")
    return root


def _c_cpp_sample_files() -> list[Path]:
    return sorted(
        p for p in SAMPLES_ROOT.rglob("*") if p.is_file() and p.suffix in _C_CPP_EXTENSIONS
    )


def test_camelcase_extension_never_reduces_candidate_count_on_existing_samples(
    tmp_path: Path,
) -> None:
    # Bản vá camelCase/PascalCase CHỈ thêm 1 nhánh #match? mới (nối bằng
    # "|"), không đổi/xoá nhánh snake_case cũ -> với BẤT KỲ sample C/C++ nào
    # đã quét được trước đây, tổng số candidate sau khi vá phải >= trước khi
    # vá (không được ít hơn). Không kỳ vọng tăng: samples/ hiện có không
    # chứa wrapper đặt tên camelCase nào (case đó đã được test riêng bằng
    # file dựng tay ở trên) — bằng nhau vẫn là kết quả hợp lệ.
    old_rules_dir = _write_pre_camelcase_rules(tmp_path / "old_rules")
    old_engine = TreeSitterEngine(rules_dir=old_rules_dir)
    new_engine = TreeSitterEngine()  # rules/ thật của dự án, đã có camelCase.

    sample_files = _c_cpp_sample_files()
    assert len(sample_files) > 0

    old_total = sum(len(old_engine.parse_file(str(f))) for f in sample_files)
    new_total = sum(len(new_engine.parse_file(str(f))) for f in sample_files)

    assert new_total >= old_total


def test_parse_file_falls_back_to_single_line_without_enclosing_function(
    engine: TreeSitterEngine, tmp_path: Path
) -> None:
    # Sink ở top-level (không nằm trong function nào) -> fallback về đúng 1
    # dòng chứa sink, không lỗi, không trả về cả file.
    top_level_file = tmp_path / "top_level.py"
    top_level_file.write_text('import os\nos.system("ls")\n', encoding="utf-8")

    candidates = engine.parse_file(str(top_level_file))

    assert len(candidates) == 1
    assert candidates[0].snippet == 'os.system("ls")'
