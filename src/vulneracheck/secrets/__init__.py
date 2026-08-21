"""
secrets: Module for scanning hardcoded secrets / API keys in source code.

Uses a set of regex patterns to detect strings that look like hardcoded
API keys, access tokens, private keys, connection strings, etc. directly
embedded in source code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class SecretFinding:
    file_path: str
    line: int
    rule_id: str
    matched_text: str


# (rule_id, compiled_pattern)
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws-access-key-id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("generic-api-key", re.compile(r"(?i)api[_-]?key['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]")),
    ("private-key-header", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA) PRIVATE KEY-----")),
    ("slack-token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}")),
    ("generic-secret-assignment", re.compile(r"(?i)(secret|password|token)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
]


def scan_text(file_path: str, content: str) -> list[SecretFinding]:
    """Scan file content line by line, return a list of SecretFinding."""
    findings: list[SecretFinding] = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for rule_id, pattern in _SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    SecretFinding(
                        file_path=file_path,
                        line=line_no,
                        rule_id=rule_id,
                        matched_text=match.group(0),
                    )
                )
    return findings


def scan_file(file_path: str) -> list[SecretFinding]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return scan_text(file_path, content)
