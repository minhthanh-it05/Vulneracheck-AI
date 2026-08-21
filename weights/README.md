# weights/

This directory contains the GraphCodeBERT model artifacts (Layer 3 —
verifier) used to binary-classify safe/vulnerable candidate sinks forwarded
by Layer 2.

`model.onnx` is tracked via **Git LFS** (see `.gitattributes` at the repo
root: `*.onnx filter=lfs diff=lfs merge=lfs -text`) — it is not a file
excluded by `.gitignore`. You need `git lfs pull` (or clone with `git lfs`
already installed) to get the real file content instead of just the LFS pointer.

## Actual files present in `weights/`

| File / directory | Description |
|---|---|
| `model.onnx` | GraphCodeBERT (RoBERTa-based) model fine-tuned for 3 languages (C/C++/Java), exported to ONNX, **opset version 14**. Format is **FP32** — see the "INT8 quantization" section below for why the quantized version isn't used. Has been run through `onnxruntime.quantization.shape_inference.quant_pre_process` before verification (the standard preprocessing step recommended by ONNX Runtime; kept because it doesn't cause errors, even though it didn't lead to a successful quantization). |
| `tokenizer/` | Full tokenizer directory in the Hugging Face `transformers` format, containing 5 files: `tokenizer.json`, `tokenizer_config.json`, `vocab.json`, `merges.txt`, `special_tokens_map.json`. Loaded via `AutoTokenizer.from_pretrained("weights/tokenizer")`. |
| `threshold_config.json` | Calibrated threshold + uncertain-zone configuration, see details below. |

### `threshold_config.json` — structure and meaning

```json
{
  "thresholds": {"c": 0.6, "cpp": 0.1, "java": 0.05},
  "uncertain_zones": {
    "c": [0.52, 0.68],
    "cpp": [0.02, 0.18],
    "java": [0.011, 0.089]
  }
}
```

- `thresholds`: **each language has its own decision threshold**, not a shared 0.5 cutoff. The `P(vulnerable)` probability returned by the model is compared against that language's threshold to produce a 0/1 label. These thresholds were calibrated to reach `target_recall = 0.92` on an internal evaluation dataset, while capping the share of findings needing manual review at `max_review_pct = 0.25`.
- `uncertain_zones`: the probability range where the model isn't confident enough to conclude automatically — if `P(vulnerable)` falls in this range, `ONNXVerifier` returns `status="UNCERTAIN_NEEDS_REVIEW"` instead of `OK`, meaning the finding needs a human to look at it rather than trusting the automatic label outright.

### INT8 quantization

INT8 quantization was attempted but dropped due to accuracy degradation too
large on the attention layer of the RoBERTa-based architecture — not
accurate enough to be acceptable for production use. So the current
`model.onnx` is the **FP32** version, not a quantized one. For quantitative
details (if any), see `docs/model_card.md`.

## Supported scope

The model **only supports 3 languages: C, C++, Java** (`SUPPORTED_ML_LANGUAGES` in
`src/vulneracheck/verifier/__init__.py`). For other languages, `ONNXVerifier.predict()`
/ `predict_batch()` **do not raise an error** — they return `VerifierResult(ml_verified=False,
confidence=None, label=None, status="ML_NOT_SUPPORTED")` so the pipeline can
continue processing the remaining candidates normally.

## Known Limitations

- **Not yet tested on a real PR/repo** — only tested on the internal test
  set so far (small hand-written samples in `samples/`), not yet run
  end-to-end on any real pull request or repository.
- **Java has worse separation than C/C++** — inferred indirectly from the
  fact that Java's threshold has to be lowered very deep (0.05, vs. 0.6 for
  C) to reach `target_recall = 0.92`, suggesting the model's probability
  distribution on Java is shifted much further from the natural 0.5 mark than C/C++.
- **Risk of distribution shift** between the training data (curated
  functions/samples) and the data Layer 2 will forward in practice (a
  snippet cut around the sink, shorter context, different length/style) —
  there's no way to measure this risk directly until it's run on real data.
- **Detailed benchmark numbers (accuracy/precision/recall/F1)** — see the
  "Independent evaluation on the SVEN dataset" section in
  `docs/model_card.md` (not repeated here, to avoid the two sources
  drifting apart over time). Summary conclusion: ~50% precision on C/C++
  when measured independently — much lower than the internal estimate made at training time.

## Process for getting the model from Google Colab

1. Train / fine-tune GraphCodeBERT on Google Colab (GPU runtime).
2. Export to ONNX (opset 14).
3. Run `onnxruntime.quantization.shape_inference.quant_pre_process` to
   preprocess the model before verifying.
4. (Tried, not used) Quantize to INT8 — dropped due to too large an error,
   see the "INT8 quantization" section above. The final product uses the FP32 version straight after step 3.
5. Download to the local machine and place it into `weights/` matching the current layout:
   ```
   weights/
   ├── README.md
   ├── model.onnx
   ├── threshold_config.json
   └── tokenizer/
       ├── tokenizer.json
       ├── tokenizer_config.json
       ├── vocab.json
       ├── merges.txt
       └── special_tokens_map.json
   ```

## Note

- `src/vulneracheck/verifier/__init__.py` automatically points to
  `weights/model.onnx`, `weights/tokenizer`, `weights/threshold_config.json`
  (`DEFAULT_MODEL_PATH`, `DEFAULT_TOKENIZER_PATH`,
  `DEFAULT_THRESHOLD_CONFIG_PATH`). If you move/rename these files, update
  these constants accordingly.
