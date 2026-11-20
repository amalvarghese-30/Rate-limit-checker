from __future__ import annotations

import ipaddress
import socket
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

# Hop-by-hop & transport-altering headers that clients should not arbitrarily inject
FORBIDDEN_HEADERS: Set[str] = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "upgrade",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
}

# Sensitive header names whose values must be masked in logs and exported profiles
SENSITIVE_HEADER_KEYS: Set[str] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "access-token",
    "x-auth-token",
    "secret",
}

METADATA_IPS: Set[str] = {
    "169.254.169.254",  # AWS / GCP / Azure metadata service
    "100.100.100.200",  # Alibaba Cloud metadata service
}


def is_ip_private_or_restricted(ip_str: str) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address is private, loopback, link-local,
    multicast, reserved, or a cloud metadata service endpoint.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True, f"Invalid IP address format: {ip_str}"

    if str(ip) in METADATA_IPS:
        return True, f"Cloud metadata endpoint blocked ({ip})"

    if ip.is_loopback:
        return True, f"Loopback address blocked ({ip})"
    if ip.is_private:
        return True, f"Private network address blocked ({ip})"
    if ip.is_link_local:
        return True, f"Link-local address blocked ({ip})"
    if ip.is_multicast:
        return True, f"Multicast address blocked ({ip})"
    if ip.is_reserved:
        return True, f"Reserved address blocked ({ip})"
    if ip.is_unspecified:
        return True, f"Unspecified address blocked ({ip})"

    return False, ""


def resolve_and_validate_hostname(hostname: str, allow_local: bool = False) -> Tuple[bool, str, List[str]]:
    """
    Resolves the hostname via DNS and checks all returned IP addresses.
    Returns (is_valid, error_message, list_of_ips).
    """
    cleaned_host = hostname.strip().lower()
    if not cleaned_host:
        return False, "Empty hostname", []

    # Block common local names unconditionally unless allow_local is True
    if not allow_local:
        if cleaned_host in ("localhost", "127.0.0.1", "::1", "0.0.0.0") or cleaned_host.endswith(".local") or cleaned_host.endswith(".internal"):
            return False, f"Local or internal hostname '{cleaned_host}' is blocked for SSRF protection", []

    try:
        # Resolve both IPv4 and IPv6
        addr_info = socket.getaddrinfo(cleaned_host, None)
    except socket.gaierror as exc:
        return False, f"DNS resolution failed for '{cleaned_host}': {exc}", []
    except Exception as exc:
        return False, f"Resolution error for '{cleaned_host}': {exc}", []

    resolved_ips: List[str] = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        if ip_str not in resolved_ips:
            resolved_ips.append(ip_str)

    if not resolved_ips:
        return False, f"No IP addresses resolved for hostname '{cleaned_host}'", []

    if not allow_local:
        for ip in resolved_ips:
            blocked, reason = is_ip_private_or_restricted(ip)
            if blocked:
                return False, f"Target '{cleaned_host}' resolves to restricted IP: {reason}", resolved_ips

    return True, "", resolved_ips


def validate_target_url(url: str, allow_local: bool = False) -> Tuple[bool, str]:
    """
    Validates scheme, hostname, and resolved IPs for SSRF defense.
    """
    if not url or not isinstance(url, str):
        return False, "Target URL must be a non-empty string"

    url = url.strip()
    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Malformed URL: {exc}"

    if parsed.scheme not in ("http", "https"):
        return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https are permitted."

    if not parsed.hostname:
        return False, "URL missing valid hostname"

    # Validate hostname and resolved IPs
    is_valid, err_msg, _ = resolve_and_validate_hostname(parsed.hostname, allow_local=allow_local)
    if not is_valid:
        return False, err_msg

    return True, ""


def sanitize_custom_headers(headers: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
    """
    Strips forbidden hop-by-hop headers and returns (sanitized_headers, rejected_header_keys).
    """
    sanitized: Dict[str, str] = {}
    rejected: List[str] = []

    for k, v in headers.items():
        kl = k.strip().lower()
        if kl in FORBIDDEN_HEADERS:
            rejected.append(k)
        else:
            sanitized[k.strip()] = str(v).strip()

    return sanitized, rejected


def mask_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Returns a copy of headers with credentials and sensitive values masked.
    """
    masked: Dict[str, str] = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADER_KEYS:
            masked[k] = "******"
        else:
            masked[k] = v
    return masked
