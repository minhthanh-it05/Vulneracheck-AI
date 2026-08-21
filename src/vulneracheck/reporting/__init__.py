"""
reporting: Module for exporting scan results as a SARIF 2.1.0
(Static Analysis Results Interchange Format) report, used to integrate
with GitHub Code Scanning, VS Code, and other CI/CD tools.
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

# CWE group confirmed to have a systematically high false positive rate from
# the verifier (Layer 3) on C/C++ (9/9 correctly-used safe samples were
# still flagged with confidence 0.69-0.97) — see docs/model_card.md,
# section "Systematic false positives on safe buffer/format functions
# (C/C++)". Buffer-copy (CWE-120, CWE-787, CWE-125), memory-unsafe
# (CWE-119, CWE-416, CWE-476), format-string (CWE-134).
# Does NOT include command injection (CWE-78, CWE-88) or pure double-free/UAF
# via delete (CWE-416/CWE-476 when belonging to the delete group specifically,
# not this group) — those 2 groups do NOT have the same issue, and actually
# improved well after the snippet was extended. Easy to adjust as more
# evidence comes in for other sink groups.
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
    "Model verification for the C/C++ buffer/format sink group has "
    "recorded a high false positive rate in internal testing (9/9 safe "
    "samples were flagged incorrectly) — see docs/model_card.md. Needs "
    "closer manual review; do not trust the confidence score directly."
)

# Explanation for a finding with ml_verified=False (language outside
# SUPPORTED_ML_LANGUAGES) — placed here (not inlined in pipeline.py) so
# that someone reading the SARIF directly (e.g. GitHub Security tab, not
# through the CLI) also understands the meaning, not just a bare
# "ml_verified": false field.
ML_NOT_SUPPORTED_NOTE = (
    "This finding is based only on Layer 1 (secret scan) + Layer 2 (Tree-sitter "
    "rule) — the file's language is NOT within the AI model's supported scope "
    "(Layer 3, C/C++/Java only), so it has NOT been verified to filter out "
    "false positives. Confidence is much lower than a finding that went "
    "through Layer 3 — needs closer manual review."
)

REDACT_VISIBLE_PREFIX = 4


def redact_secret(matched_text: str, visible_prefix: int = REDACT_VISIBLE_PREFIX) -> str:
    """Mask the real secret value before it goes into public output (SARIF, PR
    comment). Keeps only the first `visible_prefix` characters, replacing the
    rest with "****(N more chars)". E.g.: "AKIAIOSFODNN7EXAMPLE" -> "AKIA****(16 more chars)".

    A string shorter than or equal to visible_prefix is fully masked (no
    characters revealed) to avoid a short secret being fully exposed through
    the "visible part".
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
