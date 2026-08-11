"""
cli.py: Entrypoint điều khiển lệnh CLI cho EdgeSAST-Pipeline.

Usage:
    python src/cli.py scan --path <target_path> --threshold 0.85
"""

from __future__ import annotations

import sys
from pathlib import Path

import click
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)


@click.group()
@click.version_option(version="0.1.0", prog_name="EdgeSAST-Pipeline")
def cli() -> None:
    """EdgeSAST-Pipeline: Hybrid SAST Engine (Tree-sitter + ONNX Runtime AI verifier)."""


@cli.command()
@click.option(
    "--path",
    "target_path",
    required=True,
    type=click.Path(exists=True, file_okay=True, dir_okay=True, path_type=Path),
    help="Đường dẫn tới file hoặc thư mục mã nguồn cần scan.",
)
@click.option(
    "--threshold",
    default=0.85,
    show_default=True,
    type=click.FloatRange(0.0, 1.0),
    help="Ngưỡng confidence tối thiểu (AI verifier) để một finding được báo cáo.",
)
@click.option(
    "--output",
    "output_path",
    default="report.sarif.json",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Đường dẫn file báo cáo SARIF 2.1.0 đầu ra.",
)
def scan(target_path: Path, threshold: float, output_path: Path) -> None:
    """Quét mã nguồn tại --path và xuất báo cáo SARIF."""
    click.echo(f"{Fore.CYAN}[EdgeSAST] Đang quét: {target_path}{Style.RESET_ALL}")
    click.echo(f"{Fore.CYAN}[EdgeSAST] Ngưỡng confidence: {threshold}{Style.RESET_ALL}")

    # TODO: 1. src.parsers.TreeSitterEngine -> tìm candidate sinks
    # TODO: 2. src.secrets.scan_file -> tìm hardcoded secrets
    # TODO: 3. src.verifier.ONNXVerifier -> lọc false positive theo threshold
    # TODO: 4. src.reporting.SarifReport -> ghi kết quả ra output_path

    click.echo(
        f"{Fore.YELLOW}[EdgeSAST] Pipeline scan chưa được triển khai đầy đủ "
        f"(khung CLI khởi tạo).{Style.RESET_ALL}"
    )
    click.echo(f"{Fore.GREEN}[EdgeSAST] Báo cáo sẽ được ghi tại: {output_path}{Style.RESET_ALL}")


if __name__ == "__main__":
    cli()
