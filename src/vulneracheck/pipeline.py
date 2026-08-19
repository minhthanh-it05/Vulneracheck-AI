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
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

from vulneracheck.parsers import CandidateSink, LANGUAGE_RULE_MAP, TreeSitterEngine
from vulneracheck.reporting import (
    Finding,
    LOW_CONFIDENCE_CATEGORY_NOTE,
    LOW_CONFIDENCE_CWE_CATEGORIES,
    ML_NOT_SUPPORTED_NOTE,
    SarifReport,
    redact_secret,
)
from vulneracheck.secrets import SecretFinding, scan_file
from vulneracheck.verifier import ONNXVerifier, VerifierResult

# Sink KHÔNG được áp dụng giảm thiểu low-confidence dù CWE trùng với
# LOW_CONFIDENCE_CWE_CATEGORIES. "delete"/"delete[]" (C++) dùng chung mã
# CWE-416/CWE-476 với nhóm memory-unsafe (free/realloc/...) trong rule .scm,
# nhưng KHÔNG bị vấn đề false positive hệ thống tương tự — ngược lại,
# confidence cải thiện rõ sau khi mở rộng snippet (0.66 -> 0.98). Loại trừ
# tường minh để tránh bị bắt nhầm chỉ vì trùng mã CWE với nhóm khác.
_LOW_CONFIDENCE_OVERRIDE_EXCLUDED_SINKS = {"delete"}

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

# Tên hiển thị cho người dùng của language_key (segment đầu trong giá trị
# LANGUAGE_RULE_MAP — xem parsers/__init__.py) khi build cảnh báo tổng hợp
# ml_unsupported. Khác _EXTENSION_LANGUAGE_MAP ở trên: map đó chỉ phục vụ
# Layer 3 (không có "python" vì Layer 3 không hỗ trợ); map này bao phủ MỌI
# ngôn ngữ Layer 2 hỗ trợ, kể cả ngôn ngữ ngoài phạm vi Layer 3.
_DISPLAY_LANGUAGE_NAMES = {
    "python": "Python",
    "java": "Java",
    "c": "C",
    "cpp": "C++",
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
    """Cấu hình chạy pipeline cho một lần scan.

    Đúng 1 trong 2 chế độ, không được cả 2 và không được thiếu cả 2 (kiểm
    tra ở đầu run_pipeline):
        - target_path: quét toàn bộ 1 file hoặc 1 thư mục (chế độ cũ).
        - diff_range: chỉ quét file thay đổi giữa 2 ref git, vd.
          "origin/main..HEAD" (chế độ mới, dùng repo_root làm nơi chạy git).
    """

    target_path: Path | None = None
    diff_range: str | None = None
    repo_root: Path = field(default_factory=Path.cwd)
    output_path: Path = Path("report.sarif.json")


@dataclass
class PipelineResult:
    """Kết quả tổng hợp sau khi chạy hết cascade 4 bước."""

    secret_findings: list[SecretFinding] = field(default_factory=list)
    candidate_sinks: list[CandidateSink] = field(default_factory=list)
    verified_findings: list[VerifierResult] = field(default_factory=list)
    report: SarifReport | None = None
    ml_unsupported_warning: str | None = None


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


def _display_language_name(file_path: str) -> str:
    """Tên ngôn ngữ để hiển thị cho người dùng, suy ra từ LANGUAGE_RULE_MAP
    (Layer 2 — phạm vi rộng hơn Layer 3, có cả "python"). Extension không có
    rule .scm nào (không nên xảy ra ở đây vì chỉ gọi cho candidate đã qua
    Layer 2) fallback về chính extension."""
    extension = Path(file_path).suffix
    rule_file = LANGUAGE_RULE_MAP.get(extension)
    if rule_file is None:
        return extension.lstrip(".") or "unknown"
    language_key = rule_file.split("/", 1)[0]
    return _DISPLAY_LANGUAGE_NAMES.get(language_key, language_key)


def build_ml_unsupported_warning(
    verified_candidates: list[tuple[CandidateSink, VerifierResult]]
) -> str | None:
    """Dựng 1 dòng cảnh báo TỔNG HỢP (không lặp lại mỗi finding) khi có
    candidate với ml_verified=False — báo cho người dùng biết các finding đó
    chỉ dựa trên Layer 1+2, chưa qua Layer 3 lọc precision nên độ tin cậy
    thấp hơn hẳn C/C++/Java.

    Trả về None nếu mọi candidate đều ml_verified=True (không có gì để cảnh
    báo) — gọi nơi dùng (CLI) chỉ in cảnh báo khi giá trị trả về khác None.
    """
    unsupported = [
        (candidate, result)
        for candidate, result in verified_candidates
        if not result.ml_verified
    ]
    if not unsupported:
        return None

    languages = sorted({_display_language_name(candidate.file_path) for candidate, _ in unsupported})
    return (
        f"⚠️  {len(unsupported)} candidate từ ngôn ngữ {', '.join(languages)} chưa qua "
        "xác minh AI (chỉ dựa trên Layer 1+2) — độ tin cậy thấp hơn nhiều so với "
        "C/C++/Java, cần review thủ công kỹ hơn."
    )


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

    Giảm thiểu false positive hệ thống (xem docs/model_card.md): với mọi
    finding mà verifier ĐÃ chạy (ml_verified=True — cả UNCERTAIN lẫn
    label=1/OK), nếu candidate.cwe thuộc LOW_CONFIDENCE_CWE_CATEGORIES
    (buffer-copy, memory-unsafe, format-string — nhóm đã xác nhận 9/9 sample
    an toàn bị flag sai), severity bị ép về "warning" bất kể confidence/label
    thật là gì, kèm properties.low_confidence_category=true + note giải
    thích. Confidence số thật KHÔNG bị xoá/làm tròn — vẫn giữ nguyên trong
    properties để đảm bảo minh bạch. "delete" bị loại trừ tường minh dù trùng
    mã CWE (xem _LOW_CONFIDENCE_OVERRIDE_EXCLUDED_SINKS) vì không bị vấn đề
    tương tự.
    """
    def _apply_low_confidence_override(finding: Finding, candidate: CandidateSink) -> None:
        if candidate.sink_name in _LOW_CONFIDENCE_OVERRIDE_EXCLUDED_SINKS:
            return
        if any(cwe in LOW_CONFIDENCE_CWE_CATEGORIES for cwe in candidate.cwe):
            finding.severity = "warning"
            finding.extra_properties["low_confidence_category"] = True
            finding.extra_properties["note"] = LOW_CONFIDENCE_CATEGORY_NOTE

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
                        "note": ML_NOT_SUPPORTED_NOTE,
                    },
                )
            )
            continue

        if result.status == "UNCERTAIN_NEEDS_REVIEW":
            uncertain_finding = Finding(
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
            _apply_low_confidence_override(uncertain_finding, candidate)
            report.add(uncertain_finding)
        elif result.label == 1:
            vulnerable_finding = Finding(
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
            _apply_low_confidence_override(vulnerable_finding, candidate)
            report.add(vulnerable_finding)
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


def _resolve_safe_path(file_path: Path, root_real: Path) -> Path | None:
    """Trả về real path đã resolve nếu file_path là 1 file thường, nằm trong
    root_real, và không phải symlink; trả về None (kèm cảnh báo stderr) nếu
    bị loại. Dùng chung cho cả duyệt thư mục (_iter_scannable_files) và chế
    độ --diff (get_changed_files) để áp dụng đúng 1 bộ điều kiện an toàn,
    không viết lại logic ở 2 nơi.
    """
    try:
        if file_path.is_symlink():
            print(
                f"[vulneracheck] Bỏ qua {file_path} (symlink, không theo để tránh "
                "path traversal).",
                file=sys.stderr,
            )
            return None
        real_path = file_path.resolve()
        if not real_path.is_relative_to(root_real):
            print(
                f"[vulneracheck] Bỏ qua {file_path} (resolve ra ngoài thư mục gốc "
                f"{root_real}).",
                file=sys.stderr,
            )
            return None
        if not real_path.is_file():
            return None
    except OSError:
        return None
    return real_path


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
            real_path = _resolve_safe_path(file_path, root_real)
            if real_path is not None and _should_scan_file(real_path):
                yield file_path


def get_changed_files(diff_range: str, repo_root: Path) -> list[Path]:
    """Lấy danh sách file thay đổi giữa 2 ref qua `git diff --name-only
    <diff_range>`, chạy trong repo_root.

    Áp dụng ĐÚNG các điều kiện an toàn như duyệt thư mục thường (kích thước,
    binary, symlink, ngoài root) qua _resolve_safe_path/_should_scan_file —
    tái sử dụng, không viết lại. File đã bị xoá trong diff (không còn tồn
    tại ở head) tự động bị loại vì _resolve_safe_path kiểm tra is_file().

    diff_range: dạng "<base_ref>..<head_ref>", vd. "origin/main..HEAD".

    Raises:
        RuntimeError nếu không tìm thấy lệnh `git`, repo_root không phải git
        repo, hoặc ref trong diff_range không tồn tại (thông báo rõ nguyên
        nhân thường gặp, vd. thiếu `git fetch` đủ sâu trong CI).
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", diff_range],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "Không tìm thấy lệnh `git` trong PATH — cần cài Git để dùng --diff."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"`git diff --name-only {diff_range}` thất bại tại {repo_root} "
            f"(exit code {result.returncode}). Nguyên nhân thường gặp: "
            f"{repo_root} không phải git repo, hoặc ref trong '{diff_range}' "
            "không tồn tại (trong CI, cần `git fetch`/checkout đủ sâu — xem "
            f"fetch-depth). Chi tiết từ git: {result.stderr.strip()}"
        )

    root_real = repo_root.resolve()
    files: list[Path] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        file_path = repo_root / line
        real_path = _resolve_safe_path(file_path, root_real)
        if real_path is not None and _should_scan_file(real_path):
            files.append(file_path)
    return files


def run_pipeline(config: PipelineConfig) -> PipelineResult:
    """
    Chạy toàn bộ cascade: secrets -> parsers -> verifier -> reporting.

    Input:
        config: PipelineConfig — đúng 1 trong 2 chế độ:
            - target_path: quét 1 file hoặc 1 thư mục (toàn bộ).
            - diff_range: chỉ quét file thay đổi giữa 2 ref git (vd. cho
              PR), lấy qua get_changed_files(config.diff_range,
              config.repo_root).
        Set cả 2 hoặc không cái nào đều raise ValueError — 2 chế độ độc lập,
        loại trừ lẫn nhau.
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
    if config.target_path is not None and config.diff_range is not None:
        raise ValueError(
            "PipelineConfig chỉ được set 1 trong 2: target_path hoặc diff_range, "
            "không được cả 2 (2 chế độ scan loại trừ lẫn nhau)."
        )
    if config.target_path is None and config.diff_range is None:
        raise ValueError("PipelineConfig cần set target_path hoặc diff_range.")

    if config.diff_range is not None:
        files = get_changed_files(config.diff_range, config.repo_root)
    else:
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
    result.ml_unsupported_warning = build_ml_unsupported_warning(verified_candidates)
    result.report = run_reporting_layer(
        result.secret_findings, verified_candidates, config.output_path
    )

    return result
