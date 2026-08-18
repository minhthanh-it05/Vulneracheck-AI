"""
pipeline: Orchestrator điều phối luồng cascade 4 bước của VulneraCheck-AI.

Thứ tự xử lý (per-file, cho Layer 1+2; Layer 3 chạy 1 lần theo batch trên
toàn bộ candidate gom được — xem run_pipeline):
    1. secrets  (Layer 1) — quét 1 file tìm hardcoded secret/API key.
    2. parsers  (Layer 2) — parse AST bằng Tree-sitter, áp dụng rule .scm theo
       nguyên tắc high-recall: forward MỌI đoạn code "nghi vấn" (candidate sink)
       sang bước tiếp theo, chấp nhận false positive cao ở bước này để không bỏ
       sót true positive.
    3. verifier (Layer 3) — dùng model GraphCodeBERT (ONNX) phân loại nhị phân
       từng candidate: an toàn / có lỗi, lọc bớt false positive từ Layer 2.
    4. reporting — gộp kết quả từ cả 3 layer, xuất báo cáo SARIF 2.1.0.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from vulneracheck.parsers import CandidateSink, TreeSitterEngine
from vulneracheck.reporting import Finding, SarifReport, redact_secret
from vulneracheck.secrets import SecretFinding, scan_file
from vulneracheck.verifier import ONNXVerifier, VerifierResult

# Phần mở rộng file -> ngôn ngữ mà verifier (Layer 3) hỗ trợ.
# .h luôn được coi là "c" (quy ước lúc train model); .hpp/.hh/.cc/.cxx là "cpp".
_EXTENSION_LANGUAGE_MAP = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".java": "java",
}

# Thư mục luôn bị bỏ qua khi duyệt cây thư mục (tên chính xác, không phải pattern).
_SKIP_DIR_NAMES = {"node_modules", "__pycache__", "venv", ".venv"}

# Bỏ qua file lớn hơn ngưỡng này thay vì đọc hết vào RAM.
_MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB

# Số byte đọc thử ở đầu file để đoán file có phải binary hay không (có null byte).
_BINARY_SNIFF_BYTES = 8192

_verifier_singleton: ONNXVerifier | None = None
_parser_engine_singleton: TreeSitterEngine | None = None


def _get_verifier() -> ONNXVerifier:
    """Khởi tạo ONNXVerifier một lần duy nhất và tái sử dụng session cho
    mọi lần gọi run_verifier_layer trong tiến trình."""
    global _verifier_singleton
    if _verifier_singleton is None:
        from vulneracheck.verifier import (
            DEFAULT_MODEL_PATH,
            DEFAULT_THRESHOLD_CONFIG_PATH,
            DEFAULT_TOKENIZER_PATH,
        )

        _verifier_singleton = ONNXVerifier(
            model_path=DEFAULT_MODEL_PATH,
            tokenizer_path=DEFAULT_TOKENIZER_PATH,
            threshold_config_path=DEFAULT_THRESHOLD_CONFIG_PATH,
        )
    return _verifier_singleton


def _get_parser_engine() -> TreeSitterEngine:
    """Khởi tạo TreeSitterEngine một lần duy nhất — Parser/Query của từng
    ngôn ngữ đã tự cache bên trong TreeSitterEngine (xem parsers/__init__.py)."""
    global _parser_engine_singleton
    if _parser_engine_singleton is None:
        _parser_engine_singleton = TreeSitterEngine()
    return _parser_engine_singleton


@dataclass
class PipelineConfig:
    """Cấu hình chạy pipeline cho một lần scan."""

    target_path: Path
    output_path: Path = Path("report.sarif.json")


@dataclass
class PipelineResult:
    """Kết quả tổng hợp sau khi chạy hết cascade 4 bước."""

    secret_findings: list[SecretFinding] = field(default_factory=list)
    candidate_sinks: list[CandidateSink] = field(default_factory=list)
    verified_findings: list[VerifierResult] = field(default_factory=list)
    report: SarifReport | None = None


def run_secrets_layer(file_path: Path) -> list[SecretFinding]:
    """
    Layer 1: Quét regex/pattern trên 1 file (gọi thẳng secrets.scan_file có sẵn).

    Input:
        file_path: đường dẫn 1 file mã nguồn cần scan.
    Output:
        Danh sách SecretFinding — mọi hardcoded secret/API key phát hiện được.
        Kết quả layer này đi thẳng vào báo cáo cuối, KHÔNG qua verifier.
    """
    return scan_file(str(file_path))


def run_parsers_layer(file_path: Path) -> list[CandidateSink]:
    """
    Layer 2: Parse AST bằng Tree-sitter và áp rule .scm theo ngôn ngữ của file.

    Input:
        file_path: đường dẫn 1 file mã nguồn cần scan.
    Output:
        Danh sách CandidateSink — high-recall, forward TẤT CẢ match tìm được,
        không lọc thêm gì ở đây (lọc là việc của rule .scm hoặc Layer 3).
        File thuộc ngôn ngữ ngoài phạm vi hỗ trợ trả về list rỗng.
    """
    engine = _get_parser_engine()
    return engine.parse_file(str(file_path))


def run_verifier_layer(candidates: list[CandidateSink]) -> list[VerifierResult]:
    """
    Layer 3: Chạy inference GraphCodeBERT (ONNX) trên từng candidate sink.

    Threshold không còn là một tham số chung — mỗi ngôn ngữ (c/cpp/java) có
    threshold và uncertain-zone riêng, đọc từ weights/threshold_config.json
    (xem vulneracheck.verifier.ONNXVerifier).

    Input:
        candidates: danh sách CandidateSink từ Layer 2 (gom từ toàn bộ file
        đã quét). Ngôn ngữ được suy ra từ phần mở rộng file_path; candidate
        thuộc ngôn ngữ ngoài SUPPORTED_ML_LANGUAGES vẫn được trả về với
        status="ML_NOT_SUPPORTED" thay vì bị loại bỏ âm thầm.
    Output:
        Danh sách VerifierResult theo đúng thứ tự candidates đầu vào — dùng
        predict_batch (1 lần gọi ONNX session cho cả batch), không loop
        predict() từng candidate.
    """
    verifier = _get_verifier()
    items = [
        (candidate.snippet, _EXTENSION_LANGUAGE_MAP.get(Path(candidate.file_path).suffix, ""))
        for candidate in candidates
    ]
    return verifier.predict_batch(items)


def run_reporting_layer(
    secret_findings: list[SecretFinding],
    verified_candidates: list[tuple[CandidateSink, VerifierResult]],
    output_path: Path,
) -> SarifReport:
    """
    Gộp kết quả Layer 1 (secrets) và Layer 3 (verified candidates) thành một
    báo cáo SARIF 2.1.0 duy nhất, ghi ra output_path.

    Input:
        secret_findings: kết quả từ run_secrets_layer (gom từ toàn bộ file).
        verified_candidates: cặp (CandidateSink, VerifierResult) cùng vị trí
        — cần cả hai để dựng SARIF location (file/line) lẫn kết quả model,
        vì VerifierResult một mình không mang theo file_path/line.
        output_path: đường dẫn file SARIF đầu ra.
    Output:
        SarifReport đã được ghi ra đĩa tại output_path.

    Quy tắc xuất finding:
        - Secret: LUÔN redact giá trị thật qua redact_secret() trước khi đưa
          vào message — SecretFinding.matched_text chứa secret nguyên văn,
          không được lộ ra SARIF/PR comment.
        - Candidate ml_verified=False (ngôn ngữ Layer 3 không hỗ trợ): vẫn
          xuất finding (Layer 2 đã match sink nguy hiểm), severity="warning",
          properties nêu rõ chưa qua ML nên độ tin cậy thấp hơn.
        - Candidate status="UNCERTAIN_NEEDS_REVIEW": xuất finding,
          severity="warning" — model không đủ tin cậy để tự kết luận.
        - Candidate label=1 và status="OK": xuất finding, severity="error"
          — model xác nhận có lỗi.
        - Candidate label=0 và status="OK": KHÔNG xuất finding — model xác
          nhận an toàn, đây chính là false positive mà Layer 3 tồn tại để lọc.
    """
    report = SarifReport()

    for finding in secret_findings:
        redacted = redact_secret(finding.matched_text)
        report.add(
            Finding(
                rule_id=f"secret/{finding.rule_id}",
                message=f"Hardcoded secret phát hiện được (rule: {finding.rule_id}): {redacted}",
                file_path=finding.file_path,
                start_line=finding.line,
                severity="error",
                confidence=1.0,
            )
        )

    for candidate, result in verified_candidates:
        cwe_suffix = f" [{', '.join(candidate.cwe)}]" if candidate.cwe else ""
        base_properties = {"cwe": candidate.cwe} if candidate.cwe else {}

        if not result.ml_verified:
            report.add(
                Finding(
                    rule_id=f"sink/{candidate.sink_name}",
                    message=(
                        f"Candidate sink '{candidate.sink_name}'{cwe_suffix} phát hiện bởi "
                        "Layer 2, CHƯA được Layer 3 (ML) xác minh vì ngôn ngữ này không "
                        "nằm trong phạm vi hỗ trợ của model."
                    ),
                    file_path=candidate.file_path,
                    start_line=candidate.line,
                    start_column=candidate.column,
                    severity="warning",
                    confidence=0.0,
                    extra_properties={
                        **base_properties,
                        "ml_verified": False,
                        "note": "Chưa được ML xác minh, độ tin cậy thấp hơn finding đã qua Layer 3.",
                    },
                )
            )
            continue

        if result.status == "UNCERTAIN_NEEDS_REVIEW":
            report.add(
                Finding(
                    rule_id=f"sink/{candidate.sink_name}",
                    message=(
                        f"Candidate sink '{candidate.sink_name}'{cwe_suffix} — model không đủ "
                        f"tin cậy để kết luận (confidence={result.confidence:.3f} nằm trong "
                        "uncertain zone), cần review thủ công."
                    ),
                    file_path=candidate.file_path,
                    start_line=candidate.line,
                    start_column=candidate.column,
                    severity="warning",
                    confidence=result.confidence or 0.0,
                    extra_properties={
                        **base_properties,
                        "ml_verified": True,
                        "status": result.status,
                        "label": result.label,
                    },
                )
            )
        elif result.label == 1:
            report.add(
                Finding(
                    rule_id=f"sink/{candidate.sink_name}",
                    message=(
                        f"Candidate sink '{candidate.sink_name}'{cwe_suffix} — model xác nhận "
                        f"CÓ LỖI (confidence={result.confidence:.3f})."
                    ),
                    file_path=candidate.file_path,
                    start_line=candidate.line,
                    start_column=candidate.column,
                    severity="error",
                    confidence=result.confidence or 0.0,
                    extra_properties={
                        **base_properties,
                        "ml_verified": True,
                        "status": result.status,
                        "label": result.label,
                    },
                )
            )
        # label == 0 và status == "OK": model xác nhận an toàn -> không xuất
        # finding (đây chính là false positive mà Layer 3 tồn tại để lọc).

    report.write(output_path)
    return report


def _is_probably_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            chunk = f.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True
    return b"\x00" in chunk


def _should_scan_file(path: Path) -> bool:
    """Kiểm tra kích thước + binary. Không kiểm tra symlink-escape ở đây —
    việc đó chỉ có ý nghĩa khi duyệt cây thư mục (xem _iter_scannable_files),
    còn 1 file được truyền thẳng làm target là lựa chọn tường minh của người
    dùng, không phải kết quả duyệt tự động nên không có rủi ro "đi lạc"."""
    try:
        size = path.stat().st_size
    except OSError:
        print(f"[vulneracheck] Bỏ qua {path} (không đọc được kích thước file).", file=sys.stderr)
        return False
    if size > _MAX_FILE_SIZE_BYTES:
        print(
            f"[vulneracheck] Bỏ qua {path} (kích thước {size} byte > "
            f"{_MAX_FILE_SIZE_BYTES} byte, tránh đọc hết vào RAM).",
            file=sys.stderr,
        )
        return False
    if _is_probably_binary(path):
        print(f"[vulneracheck] Bỏ qua {path} (nghi ngờ là file binary).", file=sys.stderr)
        return False
    return True


def _iter_scannable_files(root: Path):
    """Duyệt cây thư mục an toàn:
        - bỏ qua .git/, node_modules/, __pycache__/, venv/.venv/, và mọi
          thư mục ẩn khác bắt đầu bằng "." (bao gồm cả .git luôn vì nó cũng
          bắt đầu bằng ".");
        - KHÔNG theo symlink (followlinks=False khi walk thư mục, và bỏ qua
          từng file là symlink hoặc resolve ra ngoài root — chặn path
          traversal qua symlink độc hại trỏ ra ngoài thư mục đang quét);
        - bỏ qua file quá lớn hoặc nghi ngờ binary (xem _should_scan_file).
    """
    root_real = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [
            d for d in dirnames if not d.startswith(".") and d not in _SKIP_DIR_NAMES
        ]
        for filename in filenames:
            file_path = Path(dirpath) / filename
            try:
                if file_path.is_symlink():
                    print(
                        f"[vulneracheck] Bỏ qua {file_path} (symlink, không theo để tránh "
                        "path traversal).",
                        file=sys.stderr,
                    )
                    continue
                real_path = file_path.resolve()
                if not real_path.is_relative_to(root_real):
                    print(
                        f"[vulneracheck] Bỏ qua {file_path} (resolve ra ngoài thư mục gốc "
                        f"{root_real}).",
                        file=sys.stderr,
                    )
                    continue
                if not real_path.is_file():
                    continue
            except OSError:
                continue
            if _should_scan_file(real_path):
                yield file_path


def run_pipeline(config: PipelineConfig) -> PipelineResult:
    """
    Chạy toàn bộ cascade: secrets -> parsers -> verifier -> reporting.

    Input:
        config: PipelineConfig (target_path, output_path). target_path có
        thể là 1 file hoặc 1 thư mục (repo/PR diff checkout).
    Output:
        PipelineResult chứa kết quả trung gian của từng layer và báo cáo cuối
        (đã được ghi ra config.output_path).

    Thứ tự thực thi: Layer 1 (secrets) và Layer 2 (parsers) chạy tuần tự
    theo TỪNG FILE. Layer 3 (verifier) chạy MỘT LẦN theo batch trên toàn bộ
    CandidateSink gom được từ mọi file (dùng predict_batch, không gọi model
    riêng cho từng file) — hiệu quả hơn nhiều so với batch nhỏ lẻ mỗi file,
    và vẫn đúng yêu cầu "Layer 3 chỉ chạy cho CandidateSink, không chạy trên
    toàn bộ file".
    """
    target_path = Path(config.target_path)

    if target_path.is_file():
        files = [target_path] if _should_scan_file(target_path) else []
    else:
        files = list(_iter_scannable_files(target_path))

    result = PipelineResult()
    all_candidates: list[CandidateSink] = []

    for file_path in files:
        result.secret_findings.extend(run_secrets_layer(file_path))
        candidates = run_parsers_layer(file_path)
        result.candidate_sinks.extend(candidates)
        all_candidates.extend(candidates)

    verifier_results = run_verifier_layer(all_candidates)
    result.verified_findings = verifier_results

    verified_candidates = list(zip(all_candidates, verifier_results))
    result.report = run_reporting_layer(
        result.secret_findings, verified_candidates, config.output_path
    )

    return result
