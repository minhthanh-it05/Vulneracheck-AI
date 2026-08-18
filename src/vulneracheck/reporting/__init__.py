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

# Nhóm CWE đã xác nhận verifier (Layer 3) có tỷ lệ false positive hệ thống
# cao trên C/C++ (9/9 sample an toàn dùng đúng cách vẫn bị flag confidence
# 0.69-0.97) — xem docs/model_card.md, mục "False positive hệ thống trên họ
# hàm buffer/format an toàn (C/C++)". Buffer-copy (CWE-120, CWE-787, CWE-125),
# memory-unsafe (CWE-119, CWE-416, CWE-476), format-string (CWE-134).
# KHÔNG bao gồm command injection (CWE-78, CWE-88) hay double-free/UAF thuần
# qua delete (CWE-416/CWE-476 khi đứng riêng ở nhóm delete, không phải nhóm
# này) — 2 nhóm đó KHÔNG bị vấn đề tương tự, ngược lại cải thiện tốt sau khi
# mở rộng snippet. Dễ chỉnh sửa khi có thêm bằng chứng cho nhóm sink khác.
LOW_CONFIDENCE_CWE_CATEGORIES = [
    "CWE-120",
    "CWE-787",
    "CWE-125",
    "CWE-119",
    "CWE-416",
    "CWE-476",
    "CWE-134",
]

LOW_CONFIDENCE_CATEGORY_NOTE = (
    "Model verification cho nhóm sink buffer/format C/C++ đã ghi nhận tỷ lệ "
    "false positive cao trong kiểm thử nội bộ (9/9 sample an toàn bị flag "
    "sai) — xem docs/model_card.md. Cần review thủ công kỹ hơn, không nên "
    "tin thẳng confidence score."
)

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
