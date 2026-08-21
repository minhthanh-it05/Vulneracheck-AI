"""
Unit tests for `vulneracheck scan --server host:port` (see cli.py) — 3
behaviors that must be correctly distinguished:
    1. Server unreachable (not running/refused/timeout) -> falls back to
       running the pipeline directly in the CLI process, NO error surfaced.
    2. Server is running for real and returns a result -> the CLI uses that
       result directly, writing the --output file locally itself (the
       server doesn't write a file), does NOT run the pipeline locally.
    3. Server is running for real but the pipeline reports a real error
       (e.g. a bad git ref) -> reports that exact error + a non-zero exit
       code, does NOT fall back (unlike case 1).

`run_pipeline` is monkeypatched both on the "local" side (vulneracheck.cli)
and the "server" side (vulneracheck.server) so no real ONNX model is
needed — following the same spirit as the requires_model pattern used
elsewhere in tests/, just replaced with a fake here instead of a skip.
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
                    message="Candidate sink 'strcpy' — the model confirms it is VULNERABLE.",
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
        # The real run_pipeline() always writes the SARIF to
        # config.output_path inside run_reporting_layer() — replicate that
        # side effect here since run_pipeline is fully monkeypatched (does
        # not call report.write()).
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
    assert "Could not connect to server" in result.output
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
        raise AssertionError("Must not fall back to the local pipeline when the server is running for real.")

    monkeypatch.setattr(server_module, "run_pipeline", fake_server_run_pipeline)
    monkeypatch.setattr(cli_module, "run_pipeline", fail_if_called_local_run_pipeline)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--path", str(target), "--output", str(output), "--server", running_server],
    )

    assert result.exit_code == 0, result.output
    assert "via server" in result.output.lower()
    assert output.exists()

    sarif = json.loads(output.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"][0]["ruleId"] == "sink/from-server"


def test_scan_real_server_error_reports_error_without_fallback(
    running_server: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fake_server_run_pipeline(config):
        raise RuntimeError("ref does not exist in repo")

    def fail_if_called_local_run_pipeline(config):
        raise AssertionError(
            "The server returned a REAL error (not a connection error) — must not fall back."
        )

    monkeypatch.setattr(server_module, "run_pipeline", fake_server_run_pipeline)
    monkeypatch.setattr(cli_module, "run_pipeline", fail_if_called_local_run_pipeline)

    runner = CliRunner()
    result = runner.invoke(
        cli,
        ["scan", "--diff", "bad..ref", "--server", running_server],
    )

    assert result.exit_code != 0
    assert "ref does not exist" in result.output
    # Must NOT contain the fallback message — this is a real error, not a lost connection.
    assert "Could not connect to server" not in result.output
