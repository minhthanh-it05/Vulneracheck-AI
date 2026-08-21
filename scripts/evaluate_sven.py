"""
scripts/evaluate_sven.py: INDEPENDENT evaluation of the ONNX model (Layer 3)
already at weights/model.onnx on the SVEN dataset (HuggingFace:
bstee615/sven) — this dataset has NEVER been used at any step in the
model's training pipeline (no data leakage risk), used as a substitute for
the original test.csv from training time (lost, the file on Google Drive
is no longer accessible).

Does NOT retrain / re-fit / re-calibrate anything here — this script only
RUNS INFERENCE with the model + threshold ALREADY THERE
(weights/model.onnx + weights/threshold_config.json) and measures
performance, without changing any of the model's parameters.

To re-run:
    python scripts/evaluate_sven.py

Requirements (NOT a dependency of the vulneracheck package, only needed for
this script specifically — not declared in pyproject.toml):
    pip install huggingface_hub pyarrow

Steps:
    1. Download both splits (train + val, 803 rows total) of bstee615/sven
       from HuggingFace Hub (cached automatically via huggingface_hub, not
       re-downloaded on later runs).
    2. Filter to ONLY keep rows whose file_name has a C/C++ extension (the
       model doesn't support Python — see SUPPORTED_ML_LANGUAGES in
       vulneracheck.verifier).
    3. Build a binary test set: func_src_before -> label=1 (vulnerable),
       func_src_after -> label=0 (fixed). Re-balance to 50/50 per language
       if the counts are off (downsample the majority class, fixed seed for reproducibility).
    4. Run ONNXVerifier.predict_batch() — model + threshold AS-IS, nothing changed.
    5. Print accuracy/precision/recall/F1/confusion matrix, BROKEN DOWN by
       language (c, cpp), plus a combined C+C++ summary.
"""

from __future__ import annotations

import random
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

try:
    from huggingface_hub import hf_hub_download
except ImportError:
    print("Missing huggingface_hub — install it with: pip install huggingface_hub", file=sys.stderr)
    raise

try:
    import pyarrow.parquet as pq
except ImportError:
    print("Missing pyarrow (to read .parquet files) — install it with: pip install pyarrow", file=sys.stderr)
    raise

from vulneracheck.verifier import (
    DEFAULT_MODEL_PATH,
    DEFAULT_THRESHOLD_CONFIG_PATH,
    DEFAULT_TOKENIZER_PATH,
    ONNXVerifier,
)

DATASET_REPO_ID = "bstee615/sven"
DATASET_FILES = [
    "data/train-00000-of-00001-23ea0a39e451d835.parquet",
    "data/val-00000-of-00001-3175b48e9b496418.parquet",
]

# Extension -> language, identical to _EXTENSION_LANGUAGE_MAP in
# vulneracheck/pipeline.py (not imported directly since it's another
# module's internal "_"-prefixed constant — this script is standalone, not
# dependent on pipeline.py's internal details).
EXTENSION_LANGUAGE_MAP = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
}

RANDOM_SEED = 42


@dataclass
class EvalExample:
    code: str
    label: int  # 1 = vulnerable (func_src_before), 0 = fixed (func_src_after)
    language: str
    vul_type: str
    func_name: str


def _load_split_rows(filename: str) -> list[dict]:
    path = hf_hub_download(repo_id=DATASET_REPO_ID, repo_type="dataset", filename=filename)
    table = pq.read_table(
        path, columns=["func_name", "func_src_before", "func_src_after", "file_name", "vul_type"]
    )
    return table.to_pylist()


def build_eval_examples() -> tuple[list[EvalExample], dict]:
    """Download + filter + build the binary test set. Returns (examples,
    stats) — stats holds intermediate numbers for a transparent report
    (no row that got excluded is hidden)."""
    rows: list[dict] = []
    for filename in DATASET_FILES:
        rows.extend(_load_split_rows(filename))

    skipped_language = 0
    skipped_degenerate = 0
    examples: list[EvalExample] = []

    for row in rows:
        language = EXTENSION_LANGUAGE_MAP.get(Path(row["file_name"]).suffix)
        if language is None:
            skipped_language += 1
            continue

        before = row["func_src_before"]
        after = row["func_src_after"]
        # Skip degenerate pairs: before == after (no real change, assigning
        # 2 different labels to the same code would add noise to the test
        # set) or empty.
        if not before.strip() or not after.strip() or before == after:
            skipped_degenerate += 1
            continue

        examples.append(
            EvalExample(
                code=before, label=1, language=language, vul_type=row["vul_type"],
                func_name=row["func_name"],
            )
        )
        examples.append(
            EvalExample(
                code=after, label=0, language=language, vul_type=row["vul_type"],
                func_name=row["func_name"],
            )
        )

    stats = {
        "total_rows_downloaded": len(rows),
        "skipped_language": skipped_language,
        "skipped_degenerate": skipped_degenerate,
        "total_examples_before_balance": len(examples),
    }
    return examples, stats


def balance_50_50(examples: list[EvalExample]) -> list[EvalExample]:
    """Re-balances to 50/50 PER LANGUAGE by downsampling the majority class
    (fixed seed for reproducibility). Structurally, each original row
    always produces exactly 1 label=1 example + 1 label=0 example of the
    SAME language, so in theory it's already balanced — this function still
    checks + self-corrects so it doesn't implicitly depend on that
    assumption (e.g. if a later filtering step is added that throws off the balance)."""
    rng = random.Random(RANDOM_SEED)
    by_language_label: dict[tuple[str, int], list[EvalExample]] = defaultdict(list)
    for ex in examples:
        by_language_label[(ex.language, ex.label)].append(ex)

    languages = {lang for lang, _ in by_language_label}
    balanced: list[EvalExample] = []
    for language in sorted(languages):
        pos = by_language_label[(language, 1)]
        neg = by_language_label[(language, 0)]
        target = min(len(pos), len(neg))
        if len(pos) != len(neg):
            print(
                f"  [balancing] {language}: label=1 has {len(pos)}, label=0 has {len(neg)} "
                f"-> downsampling both to {target} (seed={RANDOM_SEED})."
            )
        balanced.extend(rng.sample(pos, target))
        balanced.extend(rng.sample(neg, target))
    return balanced


def compute_metrics(labels: list[int], preds: list[int]) -> dict:
    tp = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 1)
    fp = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 1)
    tn = sum(1 for y, p in zip(labels, preds) if y == 0 and p == 0)
    fn = sum(1 for y, p in zip(labels, preds) if y == 1 and p == 0)
    n = len(labels)

    accuracy = (tp + tn) / n if n else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    return {
        "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
    }


def print_metrics_block(title: str, metrics: dict, uncertain_count: int) -> None:
    print(f"\n--- {title} (n={metrics['n']}) ---")
    print(f"  Confusion matrix: TP={metrics['tp']}  FP={metrics['fp']}  TN={metrics['tn']}  FN={metrics['fn']}")
    print(f"  Accuracy:  {metrics['accuracy']:.4f}")
    print(f"  Precision: {metrics['precision']:.4f}")
    print(f"  Recall:    {metrics['recall']:.4f}")
    print(f"  F1:        {metrics['f1']:.4f}")
    print(f"  Candidates in the uncertain_zone (status=UNCERTAIN_NEEDS_REVIEW): {uncertain_count}")


def main() -> None:
    print(f"[1/4] Downloading dataset {DATASET_REPO_ID} from HuggingFace Hub (train + val)...")
    examples, stats = build_eval_examples()
    print(f"  Total rows downloaded: {stats['total_rows_downloaded']}")
    print(f"  Skipped (language outside C/C++, mostly Python): {stats['skipped_language']} rows")
    print(f"  Skipped (degenerate before/after pair — empty or identical): {stats['skipped_degenerate']} rows")
    print(f"  Number of examples (before+after) before balancing: {stats['total_examples_before_balance']}")

    print("\n[2/4] Re-balancing to 50/50 per language...")
    examples = balance_50_50(examples)
    for language in sorted({ex.language for ex in examples}):
        n_pos = sum(1 for ex in examples if ex.language == language and ex.label == 1)
        n_neg = sum(1 for ex in examples if ex.language == language and ex.label == 0)
        print(f"  {language}: {n_pos} label=1 / {n_neg} label=0 (total {n_pos + n_neg})")

    if not examples:
        print("No examples left after filtering/balancing — stopping, nothing to evaluate.", file=sys.stderr)
        sys.exit(1)

    print(f"\n[3/4] Loading ONNXVerifier (model: {DEFAULT_MODEL_PATH}) and running inference "
          f"on {len(examples)} examples (threshold used as-is from "
          f"{DEFAULT_THRESHOLD_CONFIG_PATH}, NOT re-calibrated)...")
    verifier = ONNXVerifier(
        model_path=DEFAULT_MODEL_PATH,
        tokenizer_path=DEFAULT_TOKENIZER_PATH,
        threshold_config_path=DEFAULT_THRESHOLD_CONFIG_PATH,
    )
    items = [(ex.code, ex.language) for ex in examples]
    results = verifier.predict_batch(items)

    print("\n[4/4] Results:")
    by_language: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for ex, result in zip(examples, results):
        assert result.ml_verified, f"Language '{ex.language}' must be in SUPPORTED_ML_LANGUAGES (already filtered in step 1)."
        by_language[ex.language].append((ex.label, result.label, result.status))

    all_labels: list[int] = []
    all_preds: list[int] = []
    for language in sorted(by_language):
        pairs = by_language[language]
        labels = [y for y, _p, _s in pairs]
        preds = [p for _y, p, _s in pairs]
        uncertain_count = sum(1 for _y, _p, s in pairs if s == "UNCERTAIN_NEEDS_REVIEW")
        metrics = compute_metrics(labels, preds)
        print_metrics_block(f"Language: {language}", metrics, uncertain_count)
        all_labels.extend(labels)
        all_preds.extend(preds)

    combined_metrics = compute_metrics(all_labels, all_preds)
    total_uncertain = sum(
        1 for pairs in by_language.values() for _y, _p, s in pairs if s == "UNCERTAIN_NEEDS_REVIEW"
    )
    print_metrics_block("COMBINED C+C++", combined_metrics, total_uncertain)

    print(
        "\nSource: SVEN dataset (HuggingFace bstee615/sven, n=803 before/after pairs, "
        "human-verified) — INDEPENDENT of this model's training data, "
        "never used at any training step before."
    )


if __name__ == "__main__":
    main()
