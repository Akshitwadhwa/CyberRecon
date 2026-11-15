from __future__ import annotations

from urllib.error import HTTPError

from cyberrecon.safe_errors import exception_metadata, redacted_exception_line


def test_exception_metadata_walks_chain_without_messages() -> None:
    class ProviderError(RuntimeError):
        status_code = 502
        code = "bad_gateway"
        request_id = "req-safe-test"

    error = ProviderError("SECRET_PROMPT authorization=SECRET incident=case-b")
    error.__cause__ = ConnectionError("SECRET_TRANSPORT")
    metadata = exception_metadata(error)
    assert metadata == {
        "exception_types": "ProviderError>ConnectionError",
        "http_status": 502,
        "provider_error_code": "bad_gateway",
        "request_id": "req-safe-test",
    }
    assert all(secret not in str(metadata) for secret in ("SECRET_PROMPT", "SECRET", "case-b"))


def test_process_error_line_contains_only_redacted_fields() -> None:
    error = RuntimeError("secret prompt, incident data, and authorization header")
    line = redacted_exception_line(error, stage="adk_execution")
    assert line == (
        "stage=adk_execution exception_types=RuntimeError "
        "http_status=none provider_error_code=none request_id=none"
    )
    assert "secret" not in line.lower()
    assert "incident" not in line.lower()
    assert "authorization" not in line.lower()


def test_http_error_status_is_extracted_without_sensitive_attributes() -> None:
    for status in (400, 401, 429, 502):
        error = HTTPError(
            "https://redacted.invalid/private",
            status,
            "SECRET_REASON",
            {"Authorization": "SECRET_HEADER"},
            None,
        )
        metadata = exception_metadata(error)
        assert metadata["exception_types"] == "HTTPError"
        assert metadata["http_status"] == status
        assert metadata["provider_error_code"] == "none"
        assert metadata["request_id"] == "none"
        assert all(secret not in str(metadata) for secret in ("SECRET_REASON", "SECRET_HEADER", "redacted.invalid"))


def test_unrelated_exception_chain_remains_safe() -> None:
    cause = ValueError("SECRET_MESSAGE")
    error = RuntimeError("another SECRET_MESSAGE")
    error.__cause__ = cause
    metadata = exception_metadata(error)
    assert metadata == {
        "exception_types": "RuntimeError>ValueError",
        "http_status": "none",
        "provider_error_code": "none",
        "request_id": "none",
    }
