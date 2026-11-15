"""One-shot webhook POST with pinned DNS, TLS verification and no proxies/redirects."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from urllib.parse import urlsplit


def post_webhook(url: str, data: bytes) -> None:
    parsed = urlsplit(url)
    host = parsed.hostname
    if not host or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Invalid webhook destination")
    # Loopback HTTP is an explicit local development facility only.
    local_http = parsed.scheme == "http" and host in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not local_http:
        raise ValueError("HTTPS webhook required")
    port = parsed.port or (80 if local_http else 443)
    if not local_http and port != 443:
        raise ValueError("HTTPS webhook port must be 443")
    answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not answers:
        raise ValueError("Webhook destination unresolved")
    for _, _, _, _, address in answers:
        ip = ipaddress.ip_address(address[0])
        if (local_http and not ip.is_loopback) or (not local_http and not ip.is_global):
            raise ValueError("Webhook address outside authorized scope")
    # Use the already checked sockaddr directly. No second name resolution,
    # proxy environment, redirect handling, or automatic request retries.
    family, kind, proto, _, address = answers[0]
    connection = http.client.HTTPConnection(host, port, timeout=10)
    sock = socket.socket(family, kind, proto)
    try:
        sock.settimeout(10)
        sock.connect(address)
        if not local_http:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        connection.sock = sock
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.request("POST", path, body=data, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError("Webhook response rejected; no redirect or retry")
    finally:
        connection.close()
        sock.close()
