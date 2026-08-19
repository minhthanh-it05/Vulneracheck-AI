"""
server.py: HTTP server tối giản (chỉ dùng http.server, thư viện chuẩn) để
giữ ONNX model (Layer 3) sống giữa nhiều lần scan liên tiếp — tránh phải trả
lại chi phí load model + tokenizer (~15-20s overhead cố định, xem
docs/model_card.md) mỗi lần `vulneracheck scan` chạy như 1 tiến trình CLI
mới. Singleton cache trong pipeline.py (_verifier_singleton) chỉ tránh load
lại NHIỀU LẦN TRONG CÙNG 1 tiến trình — không giúp được gì khi mỗi lần scan
là 1 tiến trình mới (dev gọi lặp từ shell, CI chạy nhiều job/PR trong ngày).
Giữ server sống làm 1 tiến trình dài hạn giải quyết đúng việc đó.

Thiết kế cố ý thu gọn, đúng phạm vi (không mở rộng thêm):
    - Single-threaded (http.server.HTTPServer, KHÔNG ThreadingHTTPServer) —
      request xử lý tuần tự, không cần khoá quanh ONNX session.
    - Bind CỨNG vào 127.0.0.1 — không có flag đổi bind address ở module này.
    - Không daemonize, không PID file, không double-fork — CLI `serve` chạy
      foreground tới khi Ctrl+C.
    - Model được load lazy: KHÔNG load lúc server start, mà lúc request
      /scan đầu tiên gọi tới run_pipeline() -> run_verifier_layer() ->
      pipeline._get_verifier() (singleton có sẵn, không cần thêm gì ở đây).
    - /scan KHÔNG tự ghi file SARIF ra đĩa — dùng thư mục temp tự xoá ngay
      sau request (run_reporting_layer() trong pipeline.py luôn ghi ra
      output_path, không có cách tắt việc ghi mà không đổi API pipeline.py)
      rồi trả JSON (SarifReport.to_dict() + finding/candidate count) qua
      response; CLI (client) tự ghi file --output cục bộ.
"""

from __future__ import annotations

import json
import tempfile
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from vulneracheck.pipeline import PipelineConfig, run_pipeline

DEFAULT_HOST = "127.0.0.1"

# Timeout kết nối ngắn cho client (CLI `scan --server`) — server chạy local
# (127.0.0.1), không có lý do hợp lệ nào để chờ lâu; hết timeout coi như
# "server không chạy", CLI fallback về chạy trực tiếp (xem scan_via_server).
SERVER_TIMEOUT_SECONDS = 2.0

_SCAN_PATH = "/scan"


class ServerConnectionError(Exception):
    """Không kết nối được server `vulneracheck serve` (chưa chạy, bị từ chối
    kết nối, hoặc timeout) — CLI phân biệt lỗi này với lỗi pipeline THẬT
    (server có chạy nhưng trả lỗi, vd. ref git sai) để quyết định có nên
    fallback về chạy trực tiếp hay không (chỉ fallback ở trường hợp này)."""


class ScanRequestHandler(BaseHTTPRequestHandler):
    """Xử lý request HTTP cho `vulneracheck serve`. Đúng 1 endpoint hợp lệ:
    POST /scan — mọi path/method khác trả lỗi rõ ràng thay vì hành vi mặc
    định khó hiểu của BaseHTTPRequestHandler."""

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - tên bắt buộc theo BaseHTTPRequestHandler
        # Im lặng access log mặc định (ghi thẳng ra stderr mỗi request) —
        # CLI `serve` tự in trạng thái riêng, không cần log HTTP thô đè lên.
        pass

    def do_POST(self) -> None:  # noqa: N802 - tên bắt buộc theo BaseHTTPRequestHandler
        if self.path != _SCAN_PATH:
            self._send_json(
                404, {"error": f"Không có endpoint '{self.path}', chỉ hỗ trợ POST {_SCAN_PATH}."}
            )
            return

        content_length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""
        try:
            payload = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"JSON body không hợp lệ: {exc}"})
            return

        target_path = payload.get("target_path")
        diff_range = payload.get("diff_range")
        repo_root = payload.get("repo_root")

        if target_path is not None and diff_range is not None:
            self._send_json(
                400, {"error": "Chỉ được set 1 trong 2: target_path hoặc diff_range, không cả 2."}
            )
            return
        if target_path is None and diff_range is None:
            self._send_json(400, {"error": "Cần target_path hoặc diff_range trong JSON body."})
            return

        try:
            with tempfile.TemporaryDirectory(prefix="vulneracheck-serve-") as tmpdir:
                config = PipelineConfig(
                    target_path=Path(target_path) if target_path is not None else None,
                    diff_range=diff_range,
                    repo_root=Path(repo_root) if repo_root is not None else Path.cwd(),
                    output_path=Path(tmpdir) / "report.sarif.json",
                )
                result = run_pipeline(config)
                # Đọc report.to_dict() TRƯỚC khi thoát khỏi block `with` — file
                # tạm bị xoá ngay khi tmpdir dọn dẹp, không để lại gì trên đĩa.
                report_dict = result.report.to_dict() if result.report is not None else None
        except (ValueError, RuntimeError) as exc:
            # Lỗi có thể quy về input của request (2 chế độ scan loại trừ
            # nhau, ref git sai, không phải git repo...) — 400, không phải
            # lỗi hệ thống của server.
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - biên server: lỗi pipeline không lường trước phải thành JSON có cấu trúc, không được làm crash tiến trình serve foreground đang phục vụ các request sau
            self._send_json(500, {"error": f"Lỗi không lường trước khi chạy pipeline: {exc}"})
            return

        self._send_json(
            200,
            {
                "sarif": report_dict,
                "candidate_count": len(result.candidate_sinks),
                "finding_count": len(result.report.findings) if result.report is not None else 0,
                "secret_finding_count": len(result.secret_findings),
                "ml_unsupported_warning": result.ml_unsupported_warning,
            },
        )


def create_server(host: str = DEFAULT_HOST, port: int = 0) -> HTTPServer:
    """Tạo (nhưng KHÔNG serve_forever()) 1 HTTPServer single-threaded gắn
    ScanRequestHandler. port=0 để OS tự cấp cổng trống — dùng trong test để
    tránh xung đột cổng; CLI `serve` truyền port cụ thể do người dùng chọn.
    """
    return HTTPServer((host, port), ScanRequestHandler)


def scan_via_server(
    server_address: str,
    *,
    target_path: str | None,
    diff_range: str | None,
    repo_root: str,
    timeout: float = SERVER_TIMEOUT_SECONDS,
) -> dict:
    """Gửi request POST /scan tới server đang chạy tại server_address
    (dạng "host:port"). Trả về dict đã parse từ JSON response.

    QUAN TRỌNG: response trả về có thể chứa key "error" nếu server CÓ chạy
    nhưng pipeline/handler báo lỗi thật (vd. ref git sai) — đây KHÔNG phải
    ServerConnectionError, vì server đã trả lời được. Gọi nơi dùng (CLI)
    phải tự kiểm tra "error" trong dict trả về, KHÔNG được fallback ở
    trường hợp này (xem docstring ServerConnectionError).

    Raises:
        ServerConnectionError: không kết nối được server (chưa chạy, bị từ
        chối kết nối, timeout, DNS lookup thất bại...) — CLI nên fallback
        về chạy trực tiếp khi gặp lỗi này.
    """
    host, _, port_str = server_address.rpartition(":")
    if not host or not port_str:
        raise ValueError(f"server_address phải dạng 'host:port', nhận: {server_address!r}")

    payload = {
        "target_path": target_path,
        "diff_range": diff_range,
        "repo_root": repo_root,
    }
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"http://{host}:{port_str}{_SCAN_PATH}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL dựng từ server_address do người dùng CLI tự cung cấp (localhost only theo thiết kế), không phải input từ nguồn không tin cậy
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # Server CÓ trả lời (chạy thật, đã bind cổng, đã nhận request) nhưng
        # handler trả status lỗi (400/500 kèm JSON {"error": ...}) — KHÔNG
        # phải lỗi kết nối, không được coi là ServerConnectionError.
        return json.loads(exc.read().decode("utf-8"))
    except OSError as exc:
        # urllib.error.URLError, socket.timeout, ConnectionRefusedError...
        # đều là OSError — tức KHÔNG kết nối được server (server không chạy,
        # refused, timeout, DNS lookup fail...).
        raise ServerConnectionError(str(exc)) from exc


__all__ = [
    "DEFAULT_HOST",
    "SERVER_TIMEOUT_SECONDS",
    "ScanRequestHandler",
    "ServerConnectionError",
    "create_server",
    "scan_via_server",
]
