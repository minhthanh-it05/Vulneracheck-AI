# EdgeSAST-Pipeline

**Hybrid SAST Engine** — kết hợp Tree-sitter AST parsing, rule-based sink detection,
và AI inference on-device (ONNX Runtime) để phát hiện lỗ hổng bảo mật trong mã nguồn
mà không cần gọi ra cloud (edge-first, offline-capable).

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
EdgeSAST-Pipeline/
├── assets/                  # Sơ đồ kiến trúc, hình ảnh
├── weights/                 # Model ONNX + tokenizer (không commit, xem weights/README.md)
├── rules/                   # Tree-sitter S-expression queries theo ngôn ngữ
├── samples/
│   ├── vulnerable/          # Mã mẫu có lỗi để kiểm thử phát hiện
│   └── safe/                # Mã mẫu an toàn để kiểm thử báo động giả
├── src/
│   ├── secrets/             # Quét hardcoded secrets / API keys
│   ├── parsers/             # Tree-sitter AST parser engine
│   ├── verifier/            # AI inference (ONNX Runtime) để xác minh finding
│   ├── reporting/            # Xuất báo cáo chuẩn SARIF 2.1.0
│   └── cli.py                # Entrypoint CLI
├── .github/workflows/
│   └── security-gate.yml    # CI security gate
├── requirements.txt
└── LICENSE
```

## Cài đặt

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Tải model ONNX theo hướng dẫn tại [weights/README.md](weights/README.md) trước khi chạy scan.

## Sử dụng

```bash
python src/cli.py scan --path <target_path> --threshold 0.85
```

## License

[MIT](LICENSE)
