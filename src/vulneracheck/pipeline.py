"""
pipeline: Orchestrator điều phối luồng cascade 3 lớp của VulneraCheck-AI.

Thứ tự xử lý:
    1. secrets  (Layer 1) — quét toàn bộ mã nguồn tìm hardcoded secret/API key.
    2. parsers  (Layer 2) — parse AST bằng Tree-sitter, áp dụng rule .scm theo
       nguyên tắc high-recall: forward MỌI đoạn code "nghi vấn" (candidate sink)
       sang bước tiếp theo, chấp nhận false positive cao ở bước này để không bỏ
       sót true positive.
    3. verifier (Layer 3) — dùng model GraphCodeBERT (ONNX) phân loại nhị phân
       từng candidate: an toàn / có lỗi, lọc bớt false positive từ Layer 2.
    4. reporting — gộp kết quả từ cả 3 layer, xuất báo cáo SARIF 2.1.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from vulneracheck.parsers import CandidateSink
from vulneracheck.reporting import SarifReport
from vulneracheck.secrets import SecretFinding
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

_verifier_singleton: ONNXVerifier | None = None


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


@dataclass
class PipelineConfig:
    """Cấu hình chạy pipeline cho một lần scan."""

    target_path: Path
    threshold: float = 0.85
    output_path: Path = Path("report.sarif.json")


@dataclass
class PipelineResult:
    """Kết quả tổng hợp sau khi chạy hết cascade 3 lớp."""

    secret_findings: list[SecretFinding] = field(default_factory=list)
    candidate_sinks: list[CandidateSink] = field(default_factory=list)
    verified_findings: list[VerifierResult] = field(default_factory=list)
    report: SarifReport | None = None


def run_secrets_layer(target_path: Path) -> list[SecretFinding]:
    """
    Layer 1: Quét regex/pattern trên toàn bộ file nguồn dưới target_path.

    Input:
        target_path: đường dẫn file hoặc thư mục mã nguồn cần scan.
    Output:
        Danh sách SecretFinding — mọi hardcoded secret/API key phát hiện được.
        Kết quả layer này đi thẳng vào báo cáo cuối, KHÔNG qua verifier.
    """
    raise NotImplementedError


def run_parsers_layer(target_path: Path) -> list[CandidateSink]:
    """
    Layer 2: Parse AST bằng Tree-sitter và áp rule .scm theo ngôn ngữ.

    Input:
        target_path: đường dẫn file hoặc thư mục mã nguồn cần scan.
    Output:
        Danh sách CandidateSink — high-recall, có thể chứa nhiều false positive.
        Toàn bộ candidate ở đây được forward sang Layer 3 để xác minh thêm.
    """
    raise NotImplementedError


def run_verifier_layer(candidates: list[CandidateSink]) -> list[VerifierResult]:
    """
    Layer 3: Chạy inference GraphCodeBERT (ONNX) trên từng candidate sink.

    Threshold không còn là một tham số chung — mỗi ngôn ngữ (c/cpp/java) có
    threshold và uncertain-zone riêng, đọc từ weights/threshold_config.json
    (xem vulneracheck.verifier.ONNXVerifier).

    Input:
        candidates: danh sách CandidateSink từ Layer 2. Ngôn ngữ được suy ra
        từ phần mở rộng file_path; candidate thuộc ngôn ngữ ngoài
        SUPPORTED_ML_LANGUAGES vẫn được trả về với status="ML_NOT_SUPPORTED"
        thay vì bị loại bỏ âm thầm.
    Output:
        Danh sách VerifierResult theo đúng thứ tự candidates đầu vào.
    """
    verifier = _get_verifier()
    items = [
        (candidate.snippet, _EXTENSION_LANGUAGE_MAP.get(Path(candidate.file_path).suffix, ""))
        for candidate in candidates
    ]
    return verifier.predict_batch(items)


def run_reporting_layer(
    secret_findings: list[SecretFinding],
    verified_findings: list[VerifierResult],
    output_path: Path,
) -> SarifReport:
    """
    Gộp kết quả Layer 1 (secrets) và Layer 3 (verified findings) thành một
    báo cáo SARIF 2.1.0 duy nhất, ghi ra output_path.

    Input:
        secret_findings: kết quả từ run_secrets_layer.
        verified_findings: kết quả từ run_verifier_layer.
        output_path: đường dẫn file SARIF đầu ra.
    Output:
        SarifReport đã được ghi ra đĩa tại output_path.
    """
    raise NotImplementedError


def run_pipeline(config: PipelineConfig) -> PipelineResult:
    """
    Chạy tuần tự toàn bộ cascade: secrets -> parsers -> verifier -> reporting.

    Input:
        config: PipelineConfig (target_path, threshold, output_path).
    Output:
        PipelineResult chứa kết quả trung gian của từng layer và báo cáo cuối.
    """
    raise NotImplementedError
