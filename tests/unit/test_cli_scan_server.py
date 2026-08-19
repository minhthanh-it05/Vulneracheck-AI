"""
Unit tests cho `vulneracheck scan --server host:port` (xem cli.py) — 3 hành
vi cần phân biệt đúng:
    1. Server không kết nối được (chưa chạy/refused/timeout) -> fallback về
       chạy pipeline trực tiếp trong tiến trình CLI, KHÔNG lỗi ra ngoài.
    2. Server chạy thật và trả kết quả -> CLI dùng thẳng kết quả đó, tự ghi
       file --output cục bộ (server không ghi file), KHÔNG chạy pipeline
       cục bộ.
    3. Server chạy thật nhưng pipeline báo lỗi thật (vd. ref git sai) ->
       báo đúng lỗi đó + exit code khác 0, KHÔNG fallback (khác hẳn case 1).

`run_pipeline` được monkeypatch cả ở phía "cục bộ" (vulneracheck.cli) lẫn
phía "server" (vulneracheck.server) để không cần model ONNX thật — theo
đúng tinh thần requires_model đã dùng ở nơi khác trong tests/, chỉ khác là
thay bằng fake vì mục tiêu ở đây là hành vi CLI/HTTP, không phải pipeline.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
from click.testing import CliRunner

import vulneracheck.cli as cli_module
import vulneracheck.server as server_module
from vulneracheck.cli import cli
from vulneracheck.parsers import CandidateSink
from vulneracheck.pipeline import PipelineResult
from vulneracheck.reporting import Finding, SarifReport
from vulneracheck.server import DEFAULT_HOST, ServerConnectionError, create_server
from vulneracheck.verifier import VerifierResult


def _fake_pipeline_result(rule_id: str = "sink/strcpy") -> PipelineResult:
    candidate = CandidateSink(
        file_path="app.c", line=1, column=1, sink_name="strcpy", snippet="strcpy(...)", cwe=[]
    )
    return PipelineResult(
        secret_findings=[],
        candidate_sinks=[candidate],
        verified_findings=[VerifierResult(ml_verified=True, confidence=0.9, label=1, status="OK")],
        report=SarifReport(
            findings=[
                Finding(
                    rule_id=rule_id,
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


@pytest.fixture
def running_server():
    httpd = create_server(DEFAULT_HOST, 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address
    try:
        yield f"{host}:{port}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


def test_scan_falls_back_to_local_pipeline_when_server_unreachable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "app.c"
    target.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    output = tmp_path / "out.sarif.json"

    def fake_scan_via_server(*args, **kwargs):
        raise ServerConnectionError("simulated: connection refused")

    local_calls = []

    def fake_run_pipeline(config):
        local_calls.append(config)
        result = _fake_pipeline_result()
        # run_pipeline() thật luôn ghi SARIF ra config.output_path bên trong
        # run_reporting_layer() — mô phỏng lại side effect đó ở đây vì
        # run_pipeline bị monkeypatch hoàn toàn (không gọi report.write()).
        result.report.write(config.output_path)
        return result

    monkeypatch.setattr(server_module, "scan_via_server", fake_scan_via_server)
    monkeypatch.setattr(cli_module, "run_pipeline", fake_run_pipeline)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--path", str(target), "--output", str(output), "--server", "127.0.0.1:1"],
    )

    assert result.exit_code == 0, result.output
    assert "Không kết nối được server" in result.output
    assert len(local_calls) == 1
    assert output.exists()


def test_scan_uses_result_from_real_running_server(
    running_server: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "app.c"
    target.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    output = tmp_path / "out.sarif.json"

    def fake_server_run_pipeline(config):
        return _fake_pipeline_result(rule_id="sink/from-server")

    def fail_if_called_local_run_pipeline(config):
        raise AssertionError("Không được fallback về pipeline cục bộ khi server chạy thật.")

    monkeypatch.setattr(server_module, "run_pipeline", fake_server_run_pipeline)
    monkeypatch.setattr(cli_module, "run_pipeline", fail_if_called_local_run_pipeline)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--path", str(target), "--output", str(output), "--server", running_server],
    )

    assert result.exit_code == 0, result.output
    assert "qua server" in result.output.lower()
    assert output.exists()

    sarif = json.loads(output.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "sink/from-server"


def test_scan_real_server_error_reports_error_without_fallback(
    running_server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_server_run_pipeline(config):
        raise RuntimeError("ref không tồn tại trong repo")

    def fail_if_called_local_run_pipeline(config):
        raise AssertionError(
            "Server trả lỗi THẬT (không phải lỗi kết nối) — không được fallback."
        )

    monkeypatch.setattr(server_module, "run_pipeline", fake_server_run_pipeline)
    monkeypatch.setattr(cli_module, "run_pipeline", fail_if_called_local_run_pipeline)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--diff", "bad..ref", "--server", running_server],
    )

    assert result.exit_code != 0
    assert "ref không tồn tại" in result.output
    # Phải KHÔNG chứa thông điệp fallback — đây là lỗi thật, không phải mất kết nối.
    assert "Không kết nối được server" not in result.output
