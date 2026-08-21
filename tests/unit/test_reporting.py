"""
Unit tests for vulneracheck.reporting — specifically redact_secret(), the
function that masks a real secret value before it goes into a public SARIF/PR comment.
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
    # A string shorter than or equal to visible_prefix must be FULLY
    # masked, must not leak verbatim through the "visible part".
    result = redact_secret("abc")
    assert result == "***"
    assert "abc" not in result


def test_redact_secret_never_leaks_full_original_text() -> None:
    secret = "FAKE-SECRET-FOR-TESTING-ONLY-1234567890"
    result = redact_secret(secret)
    assert secret not in result


def test_sarif_report_never_embeds_raw_secret_via_finding_message() -> None:
    # Light integration check: if the message is built using redact_secret
    # (the expected usage in run_reporting_layer), the original secret
    # doesn't appear in the final SARIF output.
    secret = "AKIAIOSFODNN7EXAMPLE"
    redacted = redact_secret(secret)
    report = SarifReport()
    report.add(
        Finding(
            rule_id="secret/aws-access-key-id",
            message=f"Hardcoded secret detected: {redacted}",
            file_path="app.py",
            start_line=1,
        )
    )
    serialized = str(report.to_dict())
    assert secret not in serialized
    assert "AKIA****" in serialized
