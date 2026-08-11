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
TOOL_NAME = "EdgeSAST-Pipeline"


@dataclass
class Finding:
    rule_id: str
    message: str
    file_path: str
    start_line: int
    start_column: int = 1
    severity: str = "warning"
    confidence: float = 0.0


@dataclass
class SarifReport:
    findings: list[Finding] = field(default_factory=list)

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
                    "properties": {"confidence": finding.confidence},
                }
            )

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    def write(self, output_path: str | Path) -> None:
        output_path = Path(output_path)
        output_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
