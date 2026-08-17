# VulneraCheck-AI

**Hybrid SAST Engine** — cascade 3 lớp: regex/pattern matching phát hiện hardcoded
secret, Tree-sitter AST parsing lọc high-recall candidate sink, và GraphCodeBERT
(ONNX Runtime) xác minh nhị phân an toàn/có lỗi — chạy on-device, không cần gọi cloud.

## Kiến trúc

```
Source Code ─▶ Tree-sitter Parser ─▶ Rule Matching (.scm queries) ─▶ Candidate Findings
                                                                            │
                                                                            ▼
                                                          ONNX Model (quantized) Verifier
                                                                            │
                                                                            ▼
                                                                 SARIF 2.1.0 Report
```

Xem sơ đồ chi tiết tại [assets/](assets/).

## Cấu trúc dự án

```
VulneraCheck-AI/
├── assets/                        # Sơ đồ kiến trúc, hình ảnh
├── weights/                       # Model ONNX + tokenizer + threshold_config.json (không commit binary)
├── rules/                         # Tree-sitter S-expression queries, theo ngôn ngữ (c/, cpp/, java/, python/)
├── samples/
│   ├── vulnerable/                # Mã mẫu có lỗi, theo ngôn ngữ
│   └── safe/                      # Mã mẫu an toàn, theo ngôn ngữ
├── src/vulneracheck/
│   ├── secrets/                   # Layer 1: quét hardcoded secrets / API keys
│   ├── parsers/                   # Layer 2: Tree-sitter AST parser (high-recall)
│   ├── verifier/                  # Layer 3: GraphCodeBERT (ONNX) binary classifier
│   ├── reporting/                 # Xuất báo cáo chuẩn SARIF 2.1.0
│   ├── pipeline.py                # Orchestrator: secrets -> parsers -> verifier -> reporting
│   └── cli.py                     # Entrypoint CLI
├── tests/
│   ├── unit/                      # Test từng layer riêng lẻ
│   └── integration/                # Test pipeline end-to-end
├── docs/
│   ├── architecture.md
│   └── model_card.md
├── .github/workflows/
│   └── security-gate.yml          # CI security gate
├── pyproject.toml
├── requirements.txt
└── LICENSE
```

## Cài đặt

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .
```

Tải model ONNX theo hướng dẫn tại [weights/README.md](weights/README.md) trước khi chạy scan.

## Sử dụng

```bash
vulneracheck scan --path <target_path> --threshold 0.85
# hoặc, không cài đặt package:
python -m vulneracheck.cli scan --path <target_path> --threshold 0.85
```

## License

[MIT](LICENSE)
