"""Mẫu code có lỗ hổng Command Injection (CWE-78) — dùng để test phát hiện."""

import os
import subprocess


def run_ping(host: str) -> str:
    # VULNERABLE: user input được nối trực tiếp vào lệnh shell
    return os.popen(f"ping -c 1 {host}").read()


def run_backup(filename: str) -> None:
    # VULNERABLE: shell=True cho phép injection qua filename
    subprocess.call(f"tar -czf backup.tar.gz {filename}", shell=True)


API_KEY = "AKIAIOSFODNN7EXAMPLE"  # VULNERABLE: hardcoded secret
