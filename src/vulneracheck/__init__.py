"""
vulneracheck: Hybrid SAST Engine — 4-layer cascade for detecting security vulnerabilities.

Layers:
    1. vulneracheck.secrets   — regex/pattern matching (hardcoded secrets, API keys)
    2. vulneracheck.parsers   — Tree-sitter AST parsing (high-recall candidate sinks)
    3. vulneracheck.verifier  — GraphCodeBERT (ONNX) binary classifier
    4. vulneracheck.reporting — SARIF 2.1.0 / PR comment output
"""

__version__ = "0.1.0"
