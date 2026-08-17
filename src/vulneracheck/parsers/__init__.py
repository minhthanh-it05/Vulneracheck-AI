"""
parsers: Module Tree-sitter AST parser engine.

Chịu trách nhiệm parse mã nguồn thành AST và áp dụng các query .scm
(trong thư mục rules/) để tìm candidate sink cần được verifier xác minh thêm.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"

LANGUAGE_RULE_MAP = {
    ".py": "python/python_sinks.scm",
    ".java": "java/java_sinks.scm",
}


@dataclass
class CandidateSink:
    file_path: str
    line: int
    column: int
    sink_name: str
    snippet: str


class TreeSitterEngine:
    """
    Wrapper quanh thư viện `tree-sitter`.

    Việc build/nạp grammar (.so) cho từng ngôn ngữ được thực hiện lazy,
    tuỳ theo phần mở rộng file được parse.
    """

    def __init__(self, rules_dir: Path = RULES_DIR) -> None:
        self.rules_dir = rules_dir
        self._parsers: dict[str, object] = {}

    def _load_query(self, extension: str) -> str:
        rule_file = LANGUAGE_RULE_MAP.get(extension)
        if rule_file is None:
            raise ValueError(f"Không có rule .scm cho phần mở rộng: {extension}")
        query_path = self.rules_dir / rule_file
        return query_path.read_text(encoding="utf-8")

    def parse_file(self, file_path: str) -> list[CandidateSink]:
        """
        Parse một file nguồn và trả về danh sách CandidateSink dựa trên
        query .scm tương ứng với ngôn ngữ của file.

        TODO: tích hợp `tree_sitter.Language` / `tree_sitter.Parser` thực tế
        và biên dịch grammar cho từng ngôn ngữ được hỗ trợ.
        """
        extension = Path(file_path).suffix
        self._load_query(extension)  # đảm bảo rule tồn tại
        raise NotImplementedError("Tree-sitter grammar chưa được tích hợp.")
