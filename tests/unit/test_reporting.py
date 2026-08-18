"""
Unit tests cho vulneracheck.reporting — đặc biệt là redact_secret(), hàm che
giá trị secret thật trước khi đưa vào SARIF/PR comment công khai.
"""

from __future__ import annotations

from vulneracheck.reporting import Finding, SarifReport, redact_secret


def test_redact_secret_keeps_prefix_and_hides_rest() -> None:
    result = redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert result == "AKIA****(16 more chars)"
    assert "IOSFODNN7EXAMPLE" not in result


def test_redact_secret_default_visible_prefix_is_4() -> None:
    result = redact_secret("supersecretvalue123")
    assert result.startswith("supe")
    assert "secretvalue123" not in result


def test_redact_secret_custom_visible_prefix() -> None:
    result = redact_secret("abcdefgh", visible_prefix=2)
    assert result == "ab****(6 more chars)"


def test_redact_secret_short_string_fully_hidden() -> None:
    # Chuỗi ngắn hơn hoặc bằng visible_prefix phải bị che HOÀN TOÀN,
    # không được lộ nguyên văn qua "phần hiện".
    result = redact_secret("abc")
    assert result == "***"
    assert "abc" not in result


def test_redact_secret_never_leaks_full_original_text() -> None:
    secret = "FAKE-SECRET-FOR-TESTING-ONLY-1234567890"
    result = redact_secret(secret)
    assert secret not in result


def test_sarif_report_never_embeds_raw_secret_via_finding_message() -> None:
    # Kiểm tra tích hợp nhẹ: nếu message được build bằng redact_secret (đúng
    # cách dùng dự kiến trong run_reporting_layer), secret gốc không xuất
    # hiện trong SARIF output cuối cùng.
    secret = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(secret)
    report = SarifReport()
    report.add(
        Finding(
            rule_id="secret/aws-access-key-id",
            message=f"Hardcoded secret phát hiện được: {redacted}",
            file_path="app.py",
            start_line=1,
        )
    )
    serialized = str(report.to_dict())
    assert secret not in serialized
    assert "AKIA****" in serialized
