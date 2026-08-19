"""
Unit tests cho vulneracheck.server (HTTP server tối giản giữ model sống
giữa nhiều lần scan — xem module docstring trong server.py).

Khởi động server THẬT trong thread nền, dùng port do OS tự cấp (port=0,
đọc lại qua httpd.server_address) để tránh xung đột cổng giữa các lần chạy
test. Gọi HTTP request thật (http.client, thư viện chuẩn) tới server đó —
không mock tầng HTTP.

`run_pipeline` (import vào server.py từ vulneracheck.pipeline) được
monkeypatch ở 2 test cần kiểm tra nội dung response/lỗi pipeline — tránh
phải load model ONNX thật, theo đúng tinh thần requires_model đã dùng ở
tests/integration/test_pipeline.py và tests/unit/test_verifier.py (skip khi
chưa có model thật), chỉ khác là ở đây ta thay hẳn bằng fake thay vì skip,
vì mục tiêu là test hành vi HTTP/error-handling của server, không phải
pipeline thật.
"""

from __future__ import annotations

import json
import threading
from http.client import HTTPConnection

import pytest

import vulneracheck.server as server_module
from vulneracheck.parsers import CandidateSink
from vulneracheck.pipeline import PipelineResult
from vulneracheck.reporting import Finding, SarifReport
from vulneracheck.server import DEFAULT_HOST, create_server
from vulneracheck.verifier import VerifierResult


@pytest.fixture
def running_server():
    httpd = create_server(DEFAULT_HOST, 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    try:
        yield host, port
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def _post(host: str, port: int, path: str, body: bytes) -> tuple[int, dict | None]:
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        status = response.status
        raw = response.read()
    finally:
        conn.close()
    data = json.loads(raw.decode("utf-8")) if raw else None
    return status, data


def test_wrong_endpoint_returns_404(running_server) -> None:
    host, port = running_server
    status, data = _post(host, port, "/not-scan", json.dumps({"target_path": "app.c"}).encode())

    assert status == 404
    assert "error" in data


def test_missing_target_path_and_diff_range_returns_400(running_server) -> None:
    host, port = running_server
    status, data = _post(host, port, "/scan", json.dumps({}).encode())

    assert status == 400
    assert "error" in data


def test_both_target_path_and_diff_range_returns_400(running_server) -> None:
    host, port = running_server
    body = json.dumps({"target_path": "app.c", "diff_range": "HEAD~1..HEAD"}).encode()
    status, data = _post(host, port, "/scan", body)

    assert status == 400
    assert "error" in data


def test_malformed_json_body_returns_400(running_server) -> None:
    host, port = running_server
    status, data = _post(host, port, "/scan", b"{this is not json")

    assert status == 400
    assert "error" in data


def test_empty_body_returns_400(running_server) -> None:
    host, port = running_server
    status, data = _post(host, port, "/scan", b"")

    assert status == 400
    assert "error" in data


def test_scan_success_returns_sarif_and_counts(running_server, monkeypatch) -> None:
    host, port = running_server

    candidate = CandidateSink(
        file_path="app.c", line=1, column=1, sink_name="strcpy", snippet="strcpy(...)", cwe=["CWE-120"]
    )
    fake_result = PipelineResult(
        secret_findings=[],
        candidate_sinks=[candidate],
        verified_findings=[VerifierResult(ml_verified=True, confidence=0.9, label=1, status="OK")],
        report=SarifReport(
            findings=[
                Finding(
                    rule_id="sink/strcpy",
                    message="Candidate sink 'strcpy' — model xác nhận CÓ LỖI.",
                    file_path="app.c",
                    start_line=1,
                    severity="error",
                    confidence=0.9,
                )
            ]
        ),
        ml_unsupported_warning=None,
    )

    def fake_run_pipeline(config):
        assert config.target_path is not None
        return fake_result

    monkeypatch.setattr(server_module, "run_pipeline", fake_run_pipeline)

    status, data = _post(host, port, "/scan", json.dumps({"target_path": "app.c"}).encode())

    assert status == 200
    assert data["candidate_count"] == 1
    assert data["finding_count"] == 1
    assert data["secret_finding_count"] == 0
    assert data["ml_unsupported_warning"] is None
    assert data["sarif"]["version"] == "2.1.0"
    assert data["sarif"]["runs"][0]["results"][0]["ruleId"] == "sink/strcpy"


def test_scan_pipeline_runtime_error_returns_400_with_message(running_server, monkeypatch) -> None:
    host, port = running_server

    def fake_run_pipeline(config):
        raise RuntimeError("ref không tồn tại trong repo")

    monkeypatch.setattr(server_module, "run_pipeline", fake_run_pipeline)

    status, data = _post(host, port, "/scan", json.dumps({"diff_range": "bad..ref"}).encode())

    assert status == 400
    assert "ref không tồn tại" in data["error"]


def test_scan_pipeline_unexpected_error_returns_500_with_message(running_server, monkeypatch) -> None:
    host, port = running_server

    def fake_run_pipeline(config):
        raise TypeError("model không tải được")

    monkeypatch.setattr(server_module, "run_pipeline", fake_run_pipeline)

    status, data = _post(host, port, "/scan", json.dumps({"target_path": "app.c"}).encode())

    assert status == 500
    assert "model không tải được" in data["error"]


def test_scan_does_not_leave_sarif_file_on_disk(running_server, monkeypatch, tmp_path) -> None:
    # /scan không được tự ghi file SARIF ra đĩa — dùng thư mục temp tự xoá
    # (xem docstring server.py). Kiểm tra bằng cách theo dõi output_path mà
    # ScanRequestHandler truyền cho PipelineConfig và xác nhận nó KHÔNG còn
    # tồn tại sau khi response đã trả về.
    host, port = running_server
    observed_output_paths = []

    def fake_run_pipeline(config):
        observed_output_paths.append(config.output_path)
        config.output_path.write_text("{}", encoding="utf-8")  # mô phỏng run_reporting_layer thật
        return PipelineResult(report=SarifReport())

    monkeypatch.setattr(server_module, "run_pipeline", fake_run_pipeline)

    status, _data = _post(host, port, "/scan", json.dumps({"target_path": "app.c"}).encode())

    assert status == 200
    assert len(observed_output_paths) == 1
    assert not observed_output_paths[0].exists()
