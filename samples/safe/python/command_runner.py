"""Mẫu code an toàn tương đương samples/vulnerable/command_injection.py.

Dùng để kiểm tra rằng engine KHÔNG báo động giả (false positive) trên code
đã áp dụng đúng biện pháp phòng ngừa.
"""

import os
import subprocess


def run_ping(host: str) -> str:
    # SAFE: dùng list argument, không qua shell, tránh injection
    result = subprocess.run(
        ["ping", "-c", "1", host], capture_output=True, text=True, shell=False
    )
    return result.stdout


def run_backup(filename: str) -> None:
    # SAFE: shell=False, tham số truyền dưới dạng list
    subprocess.run(["tar", "-czf", "backup.tar.gz", filename], shell=False)


def get_api_key() -> str:
    # SAFE: secret được đọc từ biến môi trường, không hardcode
    return os.environ["API_KEY"]
