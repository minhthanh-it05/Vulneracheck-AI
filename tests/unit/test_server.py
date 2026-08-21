"""
Unit tests for vulneracheck.server (the minimal HTTP server that keeps the
model alive across scans — see the module docstring in server.py).

Starts a REAL server in a background thread, using an OS-assigned port
(port=0, read back via httpd.server_address) to avoid port conflicts
between test runs. Makes real HTTP requests (http.client, standard
library) to that server — the HTTP layer is not mocked.

`run_pipeline` (imported into server.py from vulneracheck.pipeline) is
monkeypatched in the 2 tests that need to check response content/pipeline
errors — to avoid needing to load the real ONNX model, following the same
spirit as the requires_model pattern used in
tests/integration/test_pipeline.py and tests/unit/test_verifier.py (skips
when there's no real model), just replaced entirely with a fake here
instead of a skip, since the goal here is to test the server's HTTP/
error-handling behavior, not the real pipeline.
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
        raise RuntimeError("ref does not exist in repo")

    monkeypatch.setattr(server_module, "run_pipeline", fake_run_pipeline)

    status, data = _post(host, port, "/scan", json.dumps({"diff_range": "bad..ref"}).encode())

    assert status == 400
    assert "ref does not exist" in data["error"]


def test_scan_pipeline_unexpected_error_returns_500_with_message(running_server, monkeypatch) -> None:
    host, port = running_server

    def fake_run_pipeline(config):
        raise TypeError("model failed to load")

    monkeypatch.setattr(server_module, "run_pipeline", fake_run_pipeline)

    status, data = _post(host, port, "/scan", json.dumps({"target_path": "app.c"}).encode())

    assert status == 500
    assert "model failed to load" in data["error"]


def test_scan_does_not_leave_sarif_file_on_disk(running_server, monkeypatch, tmp_path) -> None:
    # /scan must not write a SARIF file to disk itself — uses a temp
    # directory that auto-deletes (see the server.py docstring). Checked by
    # tracking the output_path that ScanRequestHandler passes to
    # PipelineConfig and confirming it no longer exists once the response
    # has been returned.
    host, port = running_server
    observed_output_paths = []

    def fake_run_pipeline(config):
        observed_output_paths.append(config.output_path)
        config.output_path.write_text("{}", encoding="utf-8")  # simulates the real run_reporting_layer
        return PipelineResult(report=SarifReport())

    monkeypatch.setattr(server_module, "run_pipeline", fake_run_pipeline)

    status, _data = _post(host, port, "/scan", json.dumps({"target_path": "app.c"}).encode())

    assert status == 200
    assert len(observed_output_paths) == 1
    assert not observed_output_paths[0].exists()
