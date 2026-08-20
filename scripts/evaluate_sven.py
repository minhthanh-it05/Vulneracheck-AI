"""
scripts/evaluate_sven.py: Đánh giá ĐỘC LẬP model ONNX (Layer 3) đã có tại
weights/model.onnx trên dataset SVEN (HuggingFace: bstee615/sven) — dataset
này CHƯA TỪNG được dùng ở bất kỳ bước nào trong pipeline train model (không
có rủi ro data leakage), dùng thay cho test.csv gốc lúc train (đã mất, file
trên Google Drive không còn truy cập được).

KHÔNG train lại / fit lại / hiệu chỉnh (calibrate) gì ở đây — script này chỉ
CHẠY INFERENCE model + threshold ĐÃ CÓ (weights/model.onnx +
weights/threshold_config.json) và đo hiệu năng, không đổi bất kỳ tham số nào
của model.

Chạy lại:
    python scripts/evaluate_sven.py

Yêu cầu (KHÔNG phải dependency của package vulneracheck, chỉ cần cho riêng
script này — không khai báo trong pyproject.toml):
    pip install huggingface_hub pyarrow

Các bước:
    1. Tải cả 2 split (train + val, tổng 803 dòng) của bstee615/sven từ
       HuggingFace Hub (cache tự động qua huggingface_hub, lần chạy sau
       không tải lại).
    2. Lọc CHỈ giữ dòng có file_name đuôi C/C++ (model không hỗ trợ Python
       — xem SUPPORTED_ML_LANGUAGES trong vulneracheck.verifier).
    3. Dựng tập test nhị phân: func_src_before -> label=1 (có lỗi),
       func_src_after -> label=0 (đã fix). Cân bằng lại 50/50 theo từng
       ngôn ngữ nếu đếm ra lệch (downsample lớp đa số, seed cố định để tái
       lập được).
    4. Chạy ONNXVerifier.predict_batch() — model + threshold ĐÃ CÓ, không
       đổi gì.
    5. In accuracy/precision/recall/F1/confusion matrix, TÁCH RIÊNG theo
       từng ngôn ngữ (c, cpp), kèm tổng hợp C+C++.
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
    print("Thiếu huggingface_hub — cài tạm bằng: pip install huggingface_hub", file=sys.stderr)
    raise

try:
    import pyarrow.parquet as pq
except ImportError:
    print("Thiếu pyarrow (để đọc file .parquet) — cài tạm bằng: pip install pyarrow", file=sys.stderr)
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

# Đuôi file -> ngôn ngữ, giống hệt _EXTENSION_LANGUAGE_MAP trong
# vulneracheck/pipeline.py (không import trực tiếp vì đó là hằng số nội bộ
# "_"-prefixed của module khác — script này độc lập, không phụ thuộc chi
# tiết nội bộ của pipeline.py).
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
    label: int  # 1 = có lỗi (func_src_before), 0 = đã fix (func_src_after)
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
    """Tải + lọc + dựng tập test nhị phân. Trả về (examples, stats) —
    stats chứa số liệu trung gian để in báo cáo minh bạch (không giấu dòng
    nào bị loại)."""
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
        # Bỏ cặp thoái hoá: before == after (không có thay đổi thật, gán 2
        # nhãn khác nhau cho cùng 1 đoạn code sẽ làm nhiễu tập test) hoặc
        # rỗng.
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
    """Cân bằng lại 50/50 THEO TỪNG NGÔN NGỮ bằng downsample lớp đa số (seed
    cố định để tái lập được). Về mặt cấu trúc, mỗi dòng gốc luôn sinh đúng 1
    example label=1 + 1 example label=0 CÙNG ngôn ngữ, nên trên lý thuyết đã
    cân bằng sẵn — hàm này vẫn kiểm tra + tự sửa để không phụ thuộc ngầm vào
    giả định đó (vd. nếu sau này thêm bước lọc khác làm lệch cân bằng)."""
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
                f"  [cân bằng] {language}: label=1 có {len(pos)}, label=0 có {len(neg)} "
                f"-> downsample cả 2 về {target} (seed={RANDOM_SEED})."
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
    print(f"  Số candidate rơi vào uncertain_zone (status=UNCERTAIN_NEEDS_REVIEW): {uncertain_count}")


def main() -> None:
    print(f"[1/4] Tải dataset {DATASET_REPO_ID} từ HuggingFace Hub (train + val)...")
    examples, stats = build_eval_examples()
    print(f"  Tổng số dòng tải về: {stats['total_rows_downloaded']}")
    print(f"  Bỏ (ngôn ngữ ngoài C/C++, chủ yếu Python): {stats['skipped_language']} dòng")
    print(f"  Bỏ (cặp before/after thoái hoá — rỗng hoặc giống hệt nhau): {stats['skipped_degenerate']} dòng")
    print(f"  Số example (before+after) trước khi cân bằng: {stats['total_examples_before_balance']}")

    print("\n[2/4] Cân bằng lại 50/50 theo từng ngôn ngữ...")
    examples = balance_50_50(examples)
    for language in sorted({ex.language for ex in examples}):
        n_pos = sum(1 for ex in examples if ex.language == language and ex.label == 1)
        n_neg = sum(1 for ex in examples if ex.language == language and ex.label == 0)
        print(f"  {language}: {n_pos} label=1 / {n_neg} label=0 (tổng {n_pos + n_neg})")

    if not examples:
        print("Không còn example nào sau khi lọc/cân bằng — dừng, không có gì để đánh giá.", file=sys.stderr)
        sys.exit(1)

    print(f"\n[3/4] Nạp ONNXVerifier (model: {DEFAULT_MODEL_PATH}) và chạy inference "
          f"trên {len(examples)} example (threshold dùng nguyên trạng từ "
          f"{DEFAULT_THRESHOLD_CONFIG_PATH}, KHÔNG hiệu chỉnh lại)...")
    verifier = ONNXVerifier(
        model_path=DEFAULT_MODEL_PATH,
        tokenizer_path=DEFAULT_TOKENIZER_PATH,
        threshold_config_path=DEFAULT_THRESHOLD_CONFIG_PATH,
    )
    items = [(ex.code, ex.language) for ex in examples]
    results = verifier.predict_batch(items)

    print("\n[4/4] Kết quả:")
    by_language: dict[str, list[tuple[int, int, str]]] = defaultdict(list)
    for ex, result in zip(examples, results):
        assert result.ml_verified, f"Ngôn ngữ '{ex.language}' phải nằm trong SUPPORTED_ML_LANGUAGES (đã lọc từ bước 1)."
        by_language[ex.language].append((ex.label, result.label, result.status))

    all_labels: list[int] = []
    all_preds: list[int] = []
    for language in sorted(by_language):
        pairs = by_language[language]
        labels = [y for y, _p, _s in pairs]
        preds = [p for _y, p, _s in pairs]
        uncertain_count = sum(1 for _y, _p, s in pairs if s == "UNCERTAIN_NEEDS_REVIEW")
        metrics = compute_metrics(labels, preds)
        print_metrics_block(f"Ngôn ngữ: {language}", metrics, uncertain_count)
        all_labels.extend(labels)
        all_preds.extend(preds)

    combined_metrics = compute_metrics(all_labels, all_preds)
    total_uncertain = sum(
        1 for pairs in by_language.values() for _y, _p, s in pairs if s == "UNCERTAIN_NEEDS_REVIEW"
    )
    print_metrics_block("TỔNG HỢP C+C++", combined_metrics, total_uncertain)

    print(
        "\nNguồn: SVEN dataset (HuggingFace bstee615/sven, n=803 cặp before/after, "
        "kiểm tra thủ công bởi con người) — ĐỘC LẬP với dữ liệu train model này, "
        "chưa từng dùng ở bước train nào trước đây."
    )


if __name__ == "__main__":
    main()
