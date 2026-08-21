# VulneraCheck-AI

A static application security testing (SAST) tool that runs entirely on-device (no cloud calls) and outputs SARIF 2.1.0 reports for CI/CD and GitHub Security tab integration.

This is a research/educational project (see [Project Status](#project-status) and [Known Limitations](#known-limitations) below before relying on it for anything).

## Overview

VulneraCheck-AI detects security issues in source code using a 4-layer cascade instead of a single detector:

1. **Secrets** — regex/pattern matching for hardcoded secrets and API keys.
2. **Parsers** — Tree-sitter AST parsing with per-language `.scm` rules, high-recall by design.
3. **Verifier** — a fine-tuned GraphCodeBERT model (ONNX Runtime) that classifies candidates as vulnerable/safe.
4. **Reporting** — merges all layer output into a single SARIF 2.1.0 report.

## Architecture

```
Source Code ─▶ Secrets Scanner (Layer 1) ──────────────┐
                                                          │
             ─▶ Tree-sitter Parser + Rules (Layer 2) ─▶  │
                  high-recall candidate sinks            │
                        │                                │
                        ▼                                │
             GraphCodeBERT ONNX Verifier (Layer 3) ──▶  Reporting (Layer 4)
                  precision filtering                     │
                                                          ▼
                                                 SARIF 2.1.0 report
```

- **Layer 1 (Secrets)** and **Layer 2 (Parsers)** are deliberately **high-recall**: they are designed to over-report rather than risk missing a real issue, and do not attempt to filter out false positives themselves.
- **Layer 3 (Verifier)** exists to filter the false positives that Layer 1/2 accept by design — its job is precision, not recall. See [Known Limitations](#known-limitations) for how well it currently does this in practice.
- **Layer 4 (Reporting)** deduplicates nothing on its own; it applies severity rules (e.g. downgrading known-high-false-positive sink categories to `warning`) and writes SARIF.

## Installation & Usage

```bash
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e .
```

Download the ONNX model per [weights/README.md](weights/README.md) before scanning — `weights/model.onnx` is tracked via Git LFS and is not included by a plain checkout without `git lfs pull`.

```bash
# Scan a file or directory
vulneracheck scan --path <target_path>

# Scan only files changed between two git refs (e.g. for a PR)
vulneracheck scan --diff origin/main..HEAD

# Optional: choose the SARIF output path (default: report.sarif.json)
vulneracheck scan --path <target_path> --output report.sarif.json

# Optional: run a persistent server once, then point scans at it to
# avoid paying the ~15-20s model load cost on every CLI invocation
vulneracheck serve --port 8765
vulneracheck scan --path <target_path> --server 127.0.0.1:8765
```

`scan --server` falls back to loading the model directly in-process if it cannot reach the server (not running, refused, timed out); if the server *is* reachable but the scan itself fails (e.g. a bad `--diff` ref), that real error is reported without falling back.

## Model

- **Architecture:** GraphCodeBERT, fine-tuned as a binary sequence classifier (vulnerable / safe).
- **Format:** ONNX, **FP32**, ~476MB. INT8 quantization was attempted and **failed** — quantizing produced a 0.837 error on the 0-1 probability scale with 41% of samples misclassified relative to the FP32 output, even after following ONNX Runtime's recommended pre-processing steps. This is treated as a real limitation of dynamic quantization on this RoBERTa-family attention architecture, not a configuration mistake, and FP32 is what ships.
- **Supported languages (Layer 3 / ML verification): C, C++, Java only** (`SUPPORTED_ML_LANGUAGES` in `src/vulneracheck/verifier/__init__.py`). **Python and any other language Layer 2 has rules for (currently just Python) are scanned by Layer 1+2 only and never reach the ML verifier** — those findings are reported with `ml_verified=false` and a lower-confidence warning, not silently dropped, but they have not been filtered for false positives the way C/C++/Java findings have. Read this before trusting a Python scan result the same way as a C/C++/Java one.
- **Threshold per language** (from `weights/threshold_config.json`, calibrated at train time, used as-is — not re-tuned since):

  | Language | Threshold | Uncertain zone |
  |---|---|---|
  | C | 0.60 | [0.52, 0.68] |
  | C++ | 0.10 | [0.02, 0.18] |
  | Java | 0.05 | [0.011, 0.089] |

## Known Limitations

### Fixed

- Batch prediction had non-linear time scaling with batch size (a single long snippet could pad an entire batch) — fixed with a fixed `MAX_BATCH_SIZE=32` chunking strategy.
- Model load overhead (~15-20s) was paid on every CLI invocation — fixed by adding an optional persistent server mode (`vulneracheck serve`).
- Layer 2 missed wrapper functions around known sinks (e.g. `mpack_memcpy` wrapping `memcpy`) — fixed for both snake_case (`mpack_memcpy`) and camelCase/PascalCase (`mpackMemcpy`) naming conventions.

### Not fixed — read this before using Layer 3 output as ground truth

- **Systematic false positives on C/C++ buffer/format sinks.** The verifier assigns high confidence to correctly-used, correctly-bounded calls to functions like `strncpy`/`snprintf`/`memcpy`. Confirmed on 9/9 hand-written safe samples (all flagged) and 13/13 findings on a real production codebase (the `sds` string library) — all 13 were manually confirmed to be false positives.
- **Independent evaluation on the SVEN dataset** (HuggingFace `bstee615/sven`, 803 human-verified before/after pairs, never used in this model's training) shows near-random performance on C/C++:

  | Language | n | Accuracy | Precision | Recall | F1 |
  |---|---|---|---|---|---|
  | C | 724 | 0.4972 | 0.4982 | 0.7818 | 0.6086 |
  | C++ | 112 | 0.5089 | 0.5046 | 0.9821 | 0.6667 |

  This is far below the ~89-91% figure estimated internally at training time. That internal figure was itself an **indirect estimate** — derived from a measured train/test near-duplicate rate, not a direct measurement on genuinely independent data — and should be considered less reliable than the SVEN result above.
- **Three independent attempts to fix the model failed**, all evaluated on the same SVEN holdout: oversampling the contrastive data 18x, large-scale hard-negative mining from the training data, and contrastive loss (SupCon) with auxiliary feature injection. All three produced predictions that were statistically independent of the input — the confusion matrix had two identical rows in every attempt, meaning the predicted label distribution did not depend on whether the input was actually vulnerable or fixed. This suggests the limitation sits at the architecture/data level, not something standard fine-tuning techniques can resolve.
- **No Data Flow Graph (DFG) support for C/C++.** GraphCodeBERT's official DFG extraction only covers the original CodeSearchNet languages (Python, Java, JavaScript, PHP, Ruby, Go) plus C#. Writing a C/C++ DFG extractor from scratch would need to handle pointer dataflow with no existing reference implementation to build on; this was investigated and not pursued.
- **No independent evaluation exists for Java.** The only signal is indirect: Java's calibrated threshold (0.05) is much lower than C's (0.60), suggesting worse class separation, but this has not been measured directly.
- **Model size (476MB FP32)**, with no smaller variant available, adds meaningfully to CI cold-start time.
- **No external or independent security review** of this codebase has been done.
- **Real-world validation is limited to 2 disclosed CVEs and one clean codebase** (`sds`) — both CVEs were correctly flagged (confidence 0.9347 and 0.9389), but a sample this small does not support a general recall claim.

**Bottom line:** this matches a pattern documented in the broader vulnerability-detection literature — production SAST tools with large user bases (SonarQube, CodeQL, Snyk Code) use rule/dataflow analysis as their primary detector and treat ML as a secondary filter, not the other way around, which is consistent with the cascade design here. Given the precision numbers above, **Layer 3 output should not be used to automatically block a PR in its current state** — it is only reliable enough to prioritize findings for manual review, which is the role it was designed for in the cascade.

## Project Status

This is a research/educational project, **not production-ready**. The engineering pipeline (Tree-sitter parsing, ONNX inference, SARIF output, CI wiring) works and is covered by 94 passing tests — that verifies the *pipeline* behaves correctly, not that the *model* is accurate. See [Known Limitations](#known-limitations) above before drawing any conclusion about detection quality.

## License

[MIT](LICENSE)
