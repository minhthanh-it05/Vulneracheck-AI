"""
cli.py: Entrypoint điều khiển lệnh CLI cho VulneraCheck-AI.

Usage:
    vulneracheck scan --path <target_path>
    vulneracheck scan --diff <base_ref>..<head_ref>
"""

from __future__ import annotations

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
def scan(target_path: Path | None, diff_range: str | None, output_path: Path) -> None:
    """Quét mã nguồn (--path hoặc --diff) và xuất báo cáo SARIF."""
    if target_path is not None and diff_range is not None:
        raise click.UsageError("--path và --diff loại trừ nhau, chỉ dùng 1 trong 2.")
    if target_path is None and diff_range is None:
        raise click.UsageError("Cần cung cấp --path hoặc --diff.")

    if diff_range is not None:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Đang quét diff: {diff_range}{Style.RESET_ALL}")
        config = PipelineConfig(diff_range=diff_range, repo_root=Path.cwd(), output_path=output_path)
    else:
        click.echo(f"{Fore.CYAN}[VulneraCheck] Đang quét: {target_path}{Style.RESET_ALL}")
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


if __name__ == "__main__":
    cli()
