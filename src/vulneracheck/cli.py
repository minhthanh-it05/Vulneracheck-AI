"""
cli.py: Entrypoint điều khiển lệnh CLI cho VulneraCheck-AI.

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
    "Pipeline chưa implement đầy đủ — đây KHÔNG phải kết quả quét bảo mật "
    "thật, chỉ là placeholder."
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
    help="Đường dẫn tới file hoặc thư mục mã nguồn cần scan. Loại trừ với --diff.",
)
@click.option(
    "--diff",
    "diff_range",
    required=False,
    default=None,
    type=str,
    help=(
        "Chỉ quét file thay đổi giữa 2 ref git, vd. 'origin/main..HEAD'. "
        "Chạy `git diff --name-only` tại thư mục làm việc hiện tại (phải là "
        "git repo). Loại trừ với --path."
    ),
)
@click.option(
    "--output",
    "output_path",
    default="report.sarif.json",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Đường dẫn file báo cáo SARIF 2.1.0 đầu ra.",
)
@click.option(
    "--server",
    "server_address",
    required=False,
    default=None,
    type=str,
    help=(
        "Gửi scan tới server đang chạy qua `vulneracheck serve` (dạng "
        "'host:port') thay vì load model trực tiếp trong tiến trình CLI — "
        "tránh trả lại chi phí load model mỗi lần chạy. Tự động fallback về "
        "chạy trực tiếp nếu không kết nối được server (chưa chạy/refused/"
        "timeout). Kết hợp được với --path hoặc --diff."
    ),
)
def scan(
    target_path: Path | None,
    diff_range: str | None,
    output_path: Path,
    server_address: str | None,
) -> None:
    """Quét mã nguồn (--path hoặc --diff) và xuất báo cáo SARIF."""
    if target_path is not None and diff_range is not None:
        raise click.UsageError("--path và --diff loại trừ nhau, chỉ dùng 1 trong 2.")
    if target_path is None and diff_range is None:
        raise click.UsageError("Cần cung cấp --path hoặc --diff.")

    if diff_range is not None:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Đang quét diff: {diff_range}{Style.RESET_ALL}")
    else:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Đang quét: {target_path}{Style.RESET_ALL}")

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
                f"{Fore.YELLOW}[VulneraCheck] Không kết nối được server '{server_address}' "
                f"({exc}) — fallback về chạy trực tiếp trong tiến trình CLI.{Style.RESET_ALL}",
                err=True,
            )
        else:
            if response.get("error") is not None:
                # Server CÓ chạy nhưng pipeline báo lỗi thật (vd. ref git sai)
                # — KHÔNG fallback: fallback sẽ lặp lại đúng lỗi đó, tốn công
                # vô ích và có thể che giấu vấn đề thật.
                click.echo(
                    f"{Fore.RED}[VulneraCheck] Server báo lỗi: {response['error']}{Style.RESET_ALL}",
                    err=True,
                )
                sys.exit(2)

            output_path.write_text(
                json.dumps(response["sarif"], indent=2, ensure_ascii=False), encoding="utf-8"
            )
            click.echo(
                f"{Fore.GREEN}[VulneraCheck] Quét xong (qua server {server_address}): "
                f"{response['candidate_count']} candidate sink, {response['finding_count']} "
                f"finding được báo cáo. SARIF ghi tại: {output_path}{Style.RESET_ALL}"
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
        # Safety net: phòng trường hợp còn sót layer nào chưa nối hết. Đường
        # chạy chính (không lỗi) đã dùng pipeline thật ở nhánh else bên dưới.
        click.echo(f"{Fore.YELLOW}[VulneraCheck] {PARTIAL_PIPELINE_WARNING}{Style.RESET_ALL}", err=True)
        report = SarifReport(
            run_properties={"status": "partial", "message": PARTIAL_PIPELINE_WARNING}
        )
        report.write(output_path)
        click.echo(f"{Fore.GREEN}[VulneraCheck] Báo cáo placeholder đã ghi tại: {output_path}{Style.RESET_ALL}")
        sys.exit(1)
    except RuntimeError as exc:
        # Lỗi từ `git diff` (không phải git repo, ref không tồn tại...) —
        # báo rõ nguyên nhân, không phải bug hệ thống.
        click.echo(f"{Fore.RED}[VulneraCheck] {exc}{Style.RESET_ALL}", err=True)
        sys.exit(2)

    finding_count = len(result.report.findings) if result.report is not None else 0
    click.echo(
        f"{Fore.GREEN}[VulneraCheck] Quét xong: {len(result.candidate_sinks)} candidate sink, "
        f"{finding_count} finding được báo cáo. SARIF ghi tại: {output_path}{Style.RESET_ALL}"
    )
    if result.ml_unsupported_warning is not None:
        click.echo(f"{Fore.YELLOW}[VulneraCheck] {result.ml_unsupported_warning}{Style.RESET_ALL}")


@cli.command()
@click.option(
    "--port",
    default=8765,
    show_default=True,
    type=int,
    help="Cổng lắng nghe trên 127.0.0.1 (không có flag đổi bind address — chỉ localhost).",
)
def serve(port: int) -> None:
    """Khởi động HTTP server giữ model (Layer 3) sống giữa nhiều lần scan
    liên tiếp — tránh trả lại chi phí load model mỗi lần `scan` chạy như 1
    tiến trình mới. Chạy foreground, nhấn Ctrl+C để dừng."""
    from vulneracheck.server import DEFAULT_HOST, create_server

    httpd = create_server(DEFAULT_HOST, port)
    bound_host, bound_port = httpd.server_address
    click.echo(
        f"{Fore.CYAN}[VulneraCheck] Server đang chạy tại http://{bound_host}:{bound_port} "
        f"(POST /scan). Nhấn Ctrl+C để dừng.{Style.RESET_ALL}"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Đang dừng server...{Style.RESET_ALL}")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    cli()
