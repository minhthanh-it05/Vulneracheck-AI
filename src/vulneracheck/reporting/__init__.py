"""
reporting: Module xuất báo cáo kết quả scan theo chuẩn SARIF 2.1.0
(Static Analysis Results Interchange Format), dùng để tích hợp với
GitHub Code Scanning, VS Code, và các công cụ CI/CD khác.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
TOOL_NAME = "VulneraCheck-AI"

REDACT_VISIBLE_PREFIX = 4


def redact_secret(matched_text: str, visible_prefix: int = REDACT_VISIBLE_PREFIX) -> str:
    """Che giá trị secret thật trước khi đưa vào output công khai (SARIF, PR
    comment). Chỉ giữ lại `visible_prefix` ký tự đầu, phần còn lại thay bằng
    "****(N more chars)". Vd: "AKIAIOSFODNN7EXAMPLE" -> "AKIA****(16 more chars)".

    Chuỗi ngắn hơn hoặc bằng visible_prefix bị che hoàn toàn (không lộ ký tự
    nào) để tránh trường hợp secret ngắn bị lộ hết qua "phần hiện".
    """
    if len(matched_text) <= visible_prefix:
        return "*" * len(matched_text)
    hidden_count = len(matched_text) - visible_prefix
    return f"{matched_text[:visible_prefix]}****({hidden_count} more chars)"


@dataclass
class Finding:
    rule_id: str
    message: str
    file_path: str
    start_line: int
    start_column: int = 1
    severity: str = "warning"
    confidence: float = 0.0
    extra_properties: dict = field(default_factory=dict)


@dataclass
class SarifReport:
    findings: list[Finding] = field(default_factory=list)
    run_properties: dict = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict:
        rules = {}
        results = []

        for finding in self.findings:
            rules.setdefault(
                finding.rule_id,
                {
                    "id": finding.rule_id,
                    "shortDescription": {"text": finding.rule_id},
                },
            )
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": finding.severity,
                    "message": {"text": finding.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.file_path},
                                "region": {
                                    "startLine": finding.start_line,
                                    "startColumn": finding.start_column,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "confidence": finding.confidence,
                        **finding.extra_properties,
                    },
                }
            )

        run: dict = {
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }
        if self.run_properties:
            run["properties"] = self.run_properties

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run],
        }

    def write(self, output_path: str | Path) -> None:
        output_path = Path(output_path)
        output_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
