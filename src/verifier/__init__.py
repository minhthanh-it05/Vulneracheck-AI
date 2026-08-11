"""
verifier: Module AI inference sử dụng ONNX Runtime để xác minh (verify) các
candidate finding do rule engine (parsers/) phát hiện, nhằm giảm false positive.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

WEIGHTS_DIR = Path(__file__).resolve().parent.parent.parent / "weights"
DEFAULT_MODEL_PATH = WEIGHTS_DIR / "model_quantized.onnx"
DEFAULT_TOKENIZER_PATH = WEIGHTS_DIR / "tokenizer.json"


@dataclass
class VerificationResult:
    confidence: float
    is_vulnerable: bool


class ONNXVerifier:
    """
    Nạp model `model_quantized.onnx` bằng ONNX Runtime và chạy inference
    trên code snippet của mỗi candidate sink để tính điểm confidence.
    """

    def __init__(
        self,
        model_path: Path = DEFAULT_MODEL_PATH,
        tokenizer_path: Path = DEFAULT_TOKENIZER_PATH,
        threshold: float = 0.85,
    ) -> None:
        self.model_path = model_path
        self.tokenizer_path = tokenizer_path
        self.threshold = threshold
        self._session = None
        self._tokenizer = None

    def _ensure_loaded(self) -> None:
        if self._session is not None:
            return
        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Không tìm thấy model tại {self.model_path}. "
                "Xem weights/README.md để biết cách tải model."
            )
        import onnxruntime as ort

        self._session = ort.InferenceSession(str(self.model_path))
        # TODO: nạp tokenizer tương ứng (vd. tokenizers.Tokenizer.from_file)

    def verify(self, code_snippet: str) -> VerificationResult:
        """
        Chạy inference trên một đoạn code để xác định xác suất đây là
        lỗ hổng thật (true positive) thay vì báo động giả.
        """
        self._ensure_loaded()
        # TODO: tokenize code_snippet, chạy self._session.run(...), và
        # ánh xạ output thành confidence score.
        raise NotImplementedError("Inference pipeline chưa được triển khai.")
