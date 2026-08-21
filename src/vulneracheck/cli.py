"""
cli.py: CLI entrypoint for VulneraCheck-AI.

Usage:
    vulneracheck scan --path <target_path>
    vulneracheck scan --diff <base_ref>..<head_ref>
    vulneracheck scan --path <target_path> --server 127.0.0.1:8765
    vulneracheck serve --port 8765
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from colorama import Fore, Style, init as colorama_init

from vulneracheck.pipeline import PipelineConfig, run_pipeline
from vulneracheck.reporting import SarifReport

colorama_init(autoreset=True)

PARTIAL_PIPELINE_WARNING = (
    "Pipeline is not fully implemented yet — this is NOT a real security "
    "scan result, just a placeholder."
)


@click.group()
@click.version_option(version="0.1.0", prog_name="VulneraCheck-AI")
def cli() -> None:
    """VulneraCheck-AI: Hybrid SAST Engine (Tree-sitter + ONNX Runtime AI verifier)."""


@cli.command()
@click.option(
    "--path",
    "target_path",
    required=False,
    default=None,
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
    help="Path to the file or directory to scan. Mutually exclusive with --diff.",
)
@click.option(
    "--diff",
    "diff_range",
    required=False,
    default=None,
    type=str,
    help=(
        "Only scan files changed between 2 git refs, e.g. 'origin/main..HEAD'. "
        "Runs `git diff --name-only` in the current working directory (must "
        "be a git repo). Mutually exclusive with --path."
    ),
)
@click.option(
    "--output",
    "output_path",
    default="report.sarif.json",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Path to the output SARIF 2.1.0 report file.",
)
@click.option(
    "--server",
    "server_address",
    required=False,
    default=None,
    type=str,
    help=(
        "Send the scan to a server running via `vulneracheck serve` (format "
        "'host:port') instead of loading the model directly in the CLI "
        "process — avoids paying the model load cost every run. "
        "Automatically falls back to running directly if the server can't "
        "be reached (not running/refused/timeout). Can be combined with "
        "--path or --diff."
    ),
)
def scan(
    target_path: Path | None,
    diff_range: str | None,
    output_path: Path,
    server_address: str | None,
) -> None:
    """Scan source code (--path or --diff) and export a SARIF report."""
    if target_path is not None and diff_range is not None:
        raise click.UsageError("--path and --diff are mutually exclusive, use only one.")
    if target_path is None and diff_range is None:
        raise click.UsageError("--path or --diff is required.")

    if diff_range is not None:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Scanning diff: {diff_range}{Style.RESET_ALL}")
    else:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Scanning: {target_path}{Style.RESET_ALL}")

    if server_address is not None:
        from vulneracheck.server import ServerConnectionError, scan_via_server

        try:
            response = scan_via_server(
                server_address,
                target_path=str(target_path) if target_path is not None else None,
                diff_range=diff_range,
                repo_root=str(Path.cwd()),
            )
        except ServerConnectionError as exc:
            click.echo(
                f"{Fore.YELLOW}[VulneraCheck] Could not connect to server '{server_address}' "
                f"({exc}) — falling back to running directly in the CLI process.{Style.RESET_ALL}",
                err=True,
            )
        else:
            if response.get("error") is not None:
                # The server IS running but the pipeline reported a real
                # error (e.g. a bad git ref) — do NOT fall back: falling
                # back would just repeat the same error, wasting effort and
                # potentially hiding the real problem.
                click.echo(
                    f"{Fore.RED}[VulneraCheck] Server reported an error: {response['error']}{Style.RESET_ALL}",
                    err=True,
                )
                sys.exit(2)

            output_path.write_text(
                json.dumps(response["sarif"], indent=2, ensure_ascii=False), encoding="utf-8"
            )
            click.echo(
                f"{Fore.GREEN}[VulneraCheck] Scan complete (via server {server_address}): "
                f"{response['candidate_count']} candidate sink(s), {response['finding_count']} "
                f"finding(s) reported. SARIF written to: {output_path}{Style.RESET_ALL}"
            )
            if response.get("ml_unsupported_warning"):
                click.echo(
                    f"{Fore.YELLOW}[VulneraCheck] {response['ml_unsupported_warning']}{Style.RESET_ALL}"
                )
            return

    if diff_range is not None:
        config = PipelineConfig(diff_range=diff_range, repo_root=Path.cwd(), output_path=output_path)
    else:
        config = PipelineConfig(target_path=target_path, output_path=output_path)

    try:
        result = run_pipeline(config)
    except NotImplementedError:
        # Safety net: in case some layer wasn't fully wired up yet. The main
        # (non-error) path already uses the real pipeline in the else branch below.
        click.echo(f"{Fore.YELLOW}[VulneraCheck] {PARTIAL_PIPELINE_WARNING}{Style.RESET_ALL}", err=True)
        report = SarifReport(
            run_properties={"status": "partial", "message": PARTIAL_PIPELINE_WARNING}
        )
        report.write(output_path)
        click.echo(f"{Fore.GREEN}[VulneraCheck] Placeholder report written to: {output_path}{Style.RESET_ALL}")
        sys.exit(1)
    except RuntimeError as exc:
        # Error from `git diff` (not a git repo, ref doesn't exist...) —
        # reports the real cause, not a system bug.
        click.echo(f"{Fore.RED}[VulneraCheck] {exc}{Style.RESET_ALL}", err=True)
        sys.exit(2)

    finding_count = len(result.report.findings) if result.report is not None else 0
    click.echo(
        f"{Fore.GREEN}[VulneraCheck] Scan complete: {len(result.candidate_sinks)} candidate sink(s), "
        f"{finding_count} finding(s) reported. SARIF written to: {output_path}{Style.RESET_ALL}"
    )
    if result.ml_unsupported_warning is not None:
        click.echo(f"{Fore.YELLOW}[VulneraCheck] {result.ml_unsupported_warning}{Style.RESET_ALL}")


@cli.command()
@click.option(
    "--port",
    default=8765,
    show_default=True,
    type=int,
    help="Port to listen on, bound to 127.0.0.1 (no flag to change the bind address — localhost only).",
)
def serve(port: int) -> None:
    """Start an HTTP server that keeps the model (Layer 3) alive across
    multiple consecutive scans — avoids paying the model load cost every
    time `scan` runs as a new process. Runs in the foreground, press
    Ctrl+C to stop."""
    from vulneracheck.server import DEFAULT_HOST, create_server

    httpd = create_server(DEFAULT_HOST, port)
    bound_host, bound_port = httpd.server_address
    click.echo(
        f"{Fore.CYAN}[VulneraCheck] Server running at http://{bound_host}:{bound_port} "
        f"(POST /scan). Press Ctrl+C to stop.{Style.RESET_ALL}"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Stopping server...{Style.RESET_ALL}")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    cli()
