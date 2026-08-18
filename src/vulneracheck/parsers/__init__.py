"""
parsers: Module Tree-sitter AST parser engine.

Chịu trách nhiệm parse mã nguồn thành AST và áp dụng các query .scm
(trong thư mục rules/) để tìm candidate sink cần được verifier xác minh thêm.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Language, Parser, Query, QueryCursor

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"

#  Khớp CHÍNH XÁC với _EXTENSION_LANGUAGE_MAP trong pipeline.py — .h là "c",
# .hpp/.hh/.cc/.cxx là "cpp" (quy ước lúc train model, xem pipeline.py).
LANGUAGE_RULE_MAP = {
    ".py": "python/python_sinks.scm",
    ".java": "java/java_sinks.scm",
    ".c": "c/c_sinks.scm",
    ".h": "c/c_sinks.scm",
    ".cpp": "cpp/cpp_sinks.scm",
    ".cc": "cpp/cpp_sinks.scm",
    ".cxx": "cpp/cpp_sinks.scm",
    ".hpp": "cpp/cpp_sinks.scm",
    ".hh": "cpp/cpp_sinks.scm",
}

# language_key (segment đầu của giá trị LANGUAGE_RULE_MAP) -> package tree-sitter
# language binding tương ứng, import lazy khi cần.
_LANGUAGE_MODULE_MAP = {
    "python": "tree_sitter_python",
    "java": "tree_sitter_java",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
}

_CWE_PATTERN = re.compile(r"CWE-\d+")

# Tên node "function-level" theo từng grammar — dùng để tìm function/method
# bao quanh 1 sink khi trích snippet (function_definition: C/C++/Python;
# method_declaration/constructor_declaration: Java).
_FUNCTION_NODE_TYPES = {
    "function_definition",
    "method_declaration",
    "constructor_declaration",
}


@dataclass
class CandidateSink:
    file_path: str
    line: int
    column: int
    sink_name: str
    snippet: str
    cwe: list[str] = field(default_factory=list)


def _extract_cwe_tags(query: Query, query_text: str) -> list[list[str]]:
    """Với mỗi pattern trong query (theo đúng thứ tự pattern_index mà
    QueryCursor.matches() trả về), trích các mã CWE-XXX xuất hiện trong
    comment `;` ngay phía trên pattern đó trong file .scm gốc.

    Best-effort: nếu không tìm được comment nào ngay phía trên, trả về list
    rỗng cho pattern đó thay vì lỗi — CWE chỉ là metadata bổ sung, không bắt
    buộc để CandidateSink hợp lệ.
    """
    source_bytes = query_text.encode("utf-8")
    tags: list[list[str]] = []
    for i in range(query.pattern_count):
        start = query.start_byte_for_pattern(i)
        preceding = source_bytes[:start].decode("utf-8", errors="ignore")
        comment_lines: list[str] = []
        for line in reversed(preceding.splitlines()):
            stripped = line.strip()
            if stripped.startswith(";"):
                comment_lines.insert(0, stripped)
            elif stripped == "":
                if comment_lines:
                    break
            else:
                break
        tags.append(_CWE_PATTERN.findall(" ".join(comment_lines)))
    return tags


def _find_enclosing_function_text(node, source_bytes: bytes) -> str | None:
    """Duyệt lên các node cha của `node` (thường là node @sink.name) tới khi
    gặp function/method definition (xem _FUNCTION_NODE_TYPES) và trả về toàn
    bộ text của node đó. Trả về None nếu không tìm thấy (sink ở top-level,
    lambda, hoặc grammar không có node function-level phù hợp) — gọi nơi
    dùng phải tự fallback, hàm này không tự fallback về 1 dòng.
    """
    current = node.parent
    while current is not None:
        if current.type in _FUNCTION_NODE_TYPES:
            return source_bytes[current.start_byte : current.end_byte].decode(
                "utf-8", errors="ignore"
            )
        current = current.parent
    return None


class TreeSitterEngine:
    """
    Wrapper quanh thư viện `tree-sitter`.

    Việc build/nạp grammar cho từng ngôn ngữ được thực hiện lazy, tuỳ theo
    phần mở rộng file được parse, và cache theo language_key (vd. .c/.h dùng
    chung 1 Parser/Query "c", .cpp/.cc/.cxx/.hpp/.hh dùng chung "cpp").
    """

    def __init__(self, rules_dir: Path = RULES_DIR) -> None:
        self.rules_dir = rules_dir
        self._parsers: dict[str, tuple[Parser, Query, list[list[str]]]] = {}

    def _load_query(self, extension: str) -> str:
        rule_file = LANGUAGE_RULE_MAP.get(extension)
        if rule_file is None:
            raise ValueError(f"Không có rule .scm cho phần mở rộng: {extension}")
        query_path = self.rules_dir / rule_file
        return query_path.read_text(encoding="utf-8")

    def _load_engine(
        self, extension: str
    ) -> tuple[Parser, Query, list[list[str]]] | None:
        rule_file = LANGUAGE_RULE_MAP.get(extension)
        if rule_file is None:
            return None

        language_key = rule_file.split("/", 1)[0]
        if language_key in self._parsers:
            return self._parsers[language_key]

        module_name = _LANGUAGE_MODULE_MAP[language_key]
        ts_module = importlib.import_module(module_name)
        ts_language = Language(ts_module.language())
        parser = Parser(ts_language)

        query_text = (self.rules_dir / rule_file).read_text(encoding="utf-8")
        query = Query(ts_language, query_text)
        cwe_tags = _extract_cwe_tags(query, query_text)

        engine = (parser, query, cwe_tags)
        self._parsers[language_key] = engine
        return engine

    def parse_file(self, file_path: str) -> list[CandidateSink]:
        """
        Parse một file nguồn và trả về danh sách CandidateSink dựa trên
        query .scm tương ứng với ngôn ngữ của file.

        High-recall: MỌI match từ query được forward thành CandidateSink,
        không lọc gì thêm ở đây — lọc là việc của rule .scm (viết pattern
        chặt hơn) hoặc của Layer 3 (verifier), không phải của hàm này.

        snippet ưu tiên lấy TOÀN BỘ function/method bao quanh sink (không
        chỉ 1 dòng) — verifier (Layer 3) được train/calibrate trên dữ liệu
        function-level đầy đủ, đưa đúng ngữ cảnh này vào giúp giảm distribution
        shift so với lúc train. Nếu không tìm được function bao quanh (sink ở
        top-level, lambda phức tạp...), fallback về đúng 1 dòng chứa sink như
        trước.

        Ngôn ngữ không có rule tương ứng (ngoài phạm vi hỗ trợ) trả về list
        rỗng, KHÔNG raise lỗi — file không thuộc phạm vi quét không phải lỗi
        hệ thống.
        """
        extension = Path(file_path).suffix
        engine = self._load_engine(extension)
        if engine is None:
            return []

        parser, query, cwe_tags = engine
        source_bytes = Path(file_path).read_bytes()
        tree = parser.parse(source_bytes)
        source_lines = source_bytes.decode("utf-8", errors="ignore").splitlines()

        cursor = QueryCursor(query)
        candidates: list[CandidateSink] = []
        for pattern_index, captures in cursor.matches(tree.root_node):
            name_nodes = captures.get("sink.name")
            if not name_nodes:
                continue
            name_node = name_nodes[0]
            sink_name = source_bytes[name_node.start_byte : name_node.end_byte].decode(
                "utf-8", errors="ignore"
            )
            line = name_node.start_point[0] + 1
            column = name_node.start_point[1] + 1

            function_snippet = _find_enclosing_function_text(name_node, source_bytes)
            if function_snippet is not None:
                snippet = function_snippet
            else:
                snippet = (
                    source_lines[line - 1].strip()
                    if 0 <= line - 1 < len(source_lines)
                    else sink_name
                )
            cwe = cwe_tags[pattern_index] if pattern_index < len(cwe_tags) else []

            candidates.append(
                CandidateSink(
                    file_path=file_path,
                    line=line,
                    column=column,
                    sink_name=sink_name,
                    snippet=snippet,
                    cwe=cwe,
                )
            )
        return candidates
