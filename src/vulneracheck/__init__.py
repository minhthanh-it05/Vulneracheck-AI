"""
vulneracheck: Hybrid SAST Engine — cascade 3 lớp phát hiện lỗ hổng bảo mật.

Layers:
    1. vulneracheck.secrets   — regex/pattern matching (hardcoded secrets, API keys)
    2. vulneracheck.parsers   — Tree-sitter AST parsing (high-recall candidate sinks)
    3. vulneracheck.verifier  — GraphCodeBERT (ONNX) binary classifier
    4. vulneracheck.reporting — xuất SARIF 2.1.0 / PR comment
"""

__version__ = "0.1.0"
