from __future__ import annotations

import pytest

from app.security import (
    is_ip_private_or_restricted,
    mask_sensitive_headers,
    sanitize_custom_headers,
    validate_target_url,
)


def test_ip_restriction_checks():
    # Loopback
    blocked, reason = is_ip_private_or_restricted("127.0.0.1")
    assert blocked is True
    assert "Loopback" in reason

    # Private IPv4
    assert is_ip_private_or_restricted("10.0.0.1")[0] is True
    assert is_ip_private_or_restricted("192.168.1.50")[0] is True
    assert is_ip_private_or_restricted("172.16.0.1")[0] is True

    # Cloud metadata
    blocked, reason = is_ip_private_or_restricted("169.254.169.254")
    assert blocked is True
    assert "metadata" in reason.lower()

    # Public IPv4 (Google DNS)
    blocked, reason = is_ip_private_or_restricted("8.8.8.8")
    assert blocked is False


def test_url_validation_rejections():
    # Disallow localhost when allow_local=False
    valid, err = validate_target_url("http://localhost:8000/api", allow_local=False)
    assert valid is False
    assert "blocked" in err.lower() or "ssrf" in err.lower()

    valid, err = validate_target_url("http://127.0.0.1:8000/api", allow_local=False)
    assert valid is False

    valid, err = validate_target_url("http://169.254.169.254/latest/meta-data", allow_local=False)
    assert valid is False

    # Invalid schemes
    valid, err = validate_target_url("ftp://example.com/file", allow_local=False)
    assert valid is False
    assert "scheme" in err.lower()

    valid, err = validate_target_url("file:///etc/passwd", allow_local=False)
    assert valid is False


def test_header_sanitization():
    raw_headers = {
        "Authorization": "Bearer token123",
        "Host": "evil.internal",
        "Connection": "close",
        "X-Custom": "valid-val",
    }
    sanitized, rejected = sanitize_custom_headers(raw_headers)
    assert "Host" in rejected or "host" in [r.lower() for r in rejected]
    assert "Connection" in rejected or "connection" in [r.lower() for r in rejected]
    assert "X-Custom" in sanitized
    assert "Authorization" in sanitized


def test_sensitive_header_masking():
    headers = {
        "Authorization": "Bearer supersecret123",
        "Cookie": "session=abc",
        "User-Agent": "MyClient",
    }
    masked = mask_sensitive_headers(headers)
    assert masked["Authorization"] == "******"
    assert masked["Cookie"] == "******"
    assert masked["User-Agent"] == "MyClient"
