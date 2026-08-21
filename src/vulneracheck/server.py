"""
server.py: A minimal HTTP server (uses only http.server, the standard
library) to keep the ONNX model (Layer 3) alive across multiple
consecutive scans — avoiding paying the model + tokenizer load cost
(~15-20s fixed overhead, see docs/model_card.md) again every time
`vulneracheck scan` runs as a new CLI process. The singleton cache in
pipeline.py (_verifier_singleton) only avoids reloading MULTIPLE TIMES
WITHIN THE SAME process — it doesn't help when every scan is a new process
(a dev calling it repeatedly from the shell, CI running many jobs/PRs in a
day). Keeping the server alive as a single long-lived process solves exactly that.

Deliberately kept minimal, scoped to exactly this problem (no extra scope):
    - Single-threaded (http.server.HTTPServer, NOT ThreadingHTTPServer) —
      requests are processed sequentially, no need to lock around the ONNX session.
    - HARD-bound to 127.0.0.1 — no flag to change the bind address in this module.
    - No daemonizing, no PID file, no double-fork — the `serve` CLI runs in
      the foreground until Ctrl+C.
    - The model is loaded lazily: NOT loaded at server start, but when the
      first /scan request calls run_pipeline() -> run_verifier_layer() ->
      pipeline._get_verifier() (the existing singleton, nothing extra needed here).
    - /scan does NOT write a SARIF file to disk itself — uses a temp
      directory that's auto-deleted right after the request
      (run_reporting_layer() in pipeline.py always writes to output_path,
      there's no way to disable that write without changing pipeline.py's
      API), then returns JSON (SarifReport.to_dict() + finding/candidate
      count) in the response; the CLI (client) writes the --output file locally itself.
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

# Short connection timeout for the client (CLI `scan --server`) — the
# server runs locally (127.0.0.1), there's no valid reason to wait long;
# a timeout is treated as "server not running", and the CLI falls back to
# running directly (see scan_via_server).
SERVER_TIMEOUT_SECONDS = 2.0

_SCAN_PATH = "/scan"


class ServerConnectionError(Exception):
    """Could not connect to the `vulneracheck serve` server (not running,
    connection refused, or timed out) — the CLI distinguishes this from a
    REAL pipeline error (the server is running but returns an error, e.g. a
    bad git ref) to decide whether to fall back to running directly (only
    falls back in this case)."""


class ScanRequestHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests for `vulneracheck serve`. Exactly 1 valid
    endpoint: POST /scan — any other path/method returns a clear error
    instead of BaseHTTPRequestHandler's confusing default behavior."""

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - name required by BaseHTTPRequestHandler
        # Silence the default access log (written straight to stderr per
        # request) — the `serve` CLI prints its own status, no need for raw
        # HTTP logs on top of it.
        pass

    def do_POST(self) -> None:  # noqa: N802 - name required by BaseHTTPRequestHandler
        if self.path != _SCAN_PATH:
            self._send_json(
                404, {"error": f"No such endpoint '{self.path}', only POST {_SCAN_PATH} is supported."}
            )
            return

        content_length = int(self.headers.get("Content-Length") or 0)
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""
        try:
            payload = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError as exc:
            self._send_json(400, {"error": f"Invalid JSON body: {exc}"})
            return

        target_path = payload.get("target_path")
        diff_range = payload.get("diff_range")
        repo_root = payload.get("repo_root")

        if target_path is not None and diff_range is not None:
            self._send_json(
                400, {"error": "Only 1 of the 2 can be set: target_path or diff_range, not both."}
            )
            return
        if target_path is None and diff_range is None:
            self._send_json(400, {"error": "target_path or diff_range is required in the JSON body."})
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
                # Read report.to_dict() BEFORE leaving the `with` block — the
                # temp file is deleted as soon as tmpdir is cleaned up, nothing is left on disk.
                report_dict = result.report.to_dict() if result.report is not None else None
        except (ValueError, RuntimeError) as exc:
            # An error attributable to the request's input (the 2 scan modes
            # are mutually exclusive, a bad git ref, not a git repo...) — 400,
            # not a server system error.
            self._send_json(400, {"error": str(exc)})
            return
        except Exception as exc:  # noqa: BLE001 - server boundary: an unexpected pipeline error must become a structured JSON response, must not crash the foreground serve process that's serving later requests
            self._send_json(500, {"error": f"Unexpected error while running the pipeline: {exc}"})
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
    """Creates (but does NOT serve_forever()) a single-threaded HTTPServer
    bound to ScanRequestHandler. port=0 lets the OS assign a free port —
    used in tests to avoid port conflicts; the `serve` CLI passes a
    specific port chosen by the user.
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
    """Sends a POST /scan request to the server running at server_address
    (format "host:port"). Returns the dict parsed from the JSON response.

    IMPORTANT: the returned response may contain an "error" key if the
    server IS running but the pipeline/handler reports a real error (e.g. a
    bad git ref) — this is NOT a ServerConnectionError, since the server did
    respond. The caller (CLI) must check "error" in the returned dict
    itself, and must NOT fall back in this case (see the ServerConnectionError docstring).

    Raises:
        ServerConnectionError: could not connect to the server (not
        running, connection refused, timed out, DNS lookup failed...) — the
        CLI should fall back to running directly when this happens.
    """
    host, _, port_str = server_address.rpartition(":")
    if not host or not port_str:
        raise ValueError(f"server_address must be in 'host:port' format, got: {server_address!r}")

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
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL built from server_address, supplied by the CLI user themselves (localhost only by design), not input from an untrusted source
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        # The server DID respond (running for real, bound to the port,
        # received the request) but the handler returned an error status
        # (400/500 with JSON {"error": ...}) — NOT a connection error, must
        # not be treated as a ServerConnectionError.
        return json.loads(exc.read().decode("utf-8"))
    except OSError as exc:
        # urllib.error.URLError, socket.timeout, ConnectionRefusedError...
        # are all OSError — meaning the server could NOT be reached (not
        # running, refused, timed out, DNS lookup failed...).
        raise ServerConnectionError(str(exc)) from exc


__all__ = [
    "DEFAULT_HOST",
    "SERVER_TIMEOUT_SECONDS",
    "ScanRequestHandler",
    "ServerConnectionError",
    "create_server",
    "scan_via_server",
]
