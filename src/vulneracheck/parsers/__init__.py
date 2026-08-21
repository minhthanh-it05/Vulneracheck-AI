"""
parsers: Tree-sitter AST parser engine module.

Responsible for parsing source code into an AST and applying the .scm
queries (in the rules/ directory) to find candidate sinks that need
further verification by the verifier.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from tree_sitter import Language, Parser, Query, QueryCursor

RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"

# Matches EXACTLY _EXTENSION_LANGUAGE_MAP in pipeline.py — .h is "c",
# .hpp/.hh/.cc/.cxx are "cpp" (convention used when training the model, see pipeline.py).
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

# language_key (first segment of a LANGUAGE_RULE_MAP value) -> corresponding
# tree-sitter language binding package, imported lazily when needed.
_LANGUAGE_MODULE_MAP = {
    "python": "tree_sitter_python",
    "java": "tree_sitter_java",
    "c": "tree_sitter_c",
    "cpp": "tree_sitter_cpp",
}

_CWE_PATTERN = re.compile(r"CWE-\d+")

# "Function-level" node names per grammar — used to find the enclosing
# function/method for a sink when extracting a snippet (function_definition:
# C/C++/Python; method_declaration/constructor_declaration: Java).
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
    """For each pattern in the query (in the same pattern_index order that
    QueryCursor.matches() returns), extract the CWE-XXX codes appearing in
    the `;` comment immediately above that pattern in the original .scm file.

    Best-effort: if no comment is found immediately above, returns an empty
    list for that pattern instead of erroring — CWE is just supplementary
    metadata, not required for a CandidateSink to be valid.
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
    """Walk up the parent nodes of `node` (usually the @sink.name node)
    until hitting a function/method definition (see _FUNCTION_NODE_TYPES)
    and return the full text of that node. Returns None if not found (sink
    is top-level, a complex lambda, or the grammar has no suitable
    function-level node) — the caller must handle its own fallback, this
    function does not fall back to a single line itself.
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
    Wrapper around the `tree-sitter` library.

    Building/loading the grammar for each language is done lazily,
    depending on the extension of the file being parsed, and cached by
    language_key (e.g. .c/.h share one "c" Parser/Query,
    .cpp/.cc/.cxx/.hpp/.hh share one "cpp").
    """

    def __init__(self, rules_dir: Path = RULES_DIR) -> None:
        self.rules_dir = rules_dir
        self._parsers: dict[str, tuple[Parser, Query, list[list[str]]]] = {}

    def _load_query(self, extension: str) -> str:
        rule_file = LANGUAGE_RULE_MAP.get(extension)
        if rule_file is None:
            raise ValueError(f"No .scm rule for extension: {extension}")
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
        Parse a source file and return a list of CandidateSink based on the
        .scm query corresponding to the file's language.

        High-recall: EVERY match from the query is forwarded as a
        CandidateSink, with no further filtering here — filtering is the
        job of the .scm rule (writing a tighter pattern) or of Layer 3
        (verifier), not of this function.

        The snippet preferentially takes the ENTIRE function/method
        enclosing the sink (not just one line) — the verifier (Layer 3) is
        trained/calibrated on full function-level data, so providing this
        same context reduces distribution shift compared to training. If no
        enclosing function is found (sink is top-level, a complex lambda,
        etc.), falls back to exactly the one line containing the sink, as before.

        A language with no matching rule (outside the supported scope)
        returns an empty list, WITHOUT raising — a file outside the scan
        scope is not a system error.
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
