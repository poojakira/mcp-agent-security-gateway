"""Adversarial webhook tests; fake public DNS and disposable loopback targets."""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch

import pytest

from mcp_monitor.production.webhook_transport import post_webhook


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1", "::ffff:127.0.0.1"]
)
def test_private_metadata_and_ipv6_destinations_never_connect(address):
    with (
        patch(
            "socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))],
        ),
        patch("socket.socket") as connect,
    ):
        with pytest.raises(ValueError):
            post_webhook("https://approved.example/hook", b"{}")
        connect.assert_not_called()


@pytest.mark.parametrize(
    "url",
    [
        "http://public.example",
        "https://user:password@public.example",
        "https://public.example:8443",
        "file:///tmp/data",
        "https://public.example/#fragment",
    ],
)
def test_invalid_destination_never_resolves(url):
    with patch("socket.getaddrinfo") as resolve:
        with pytest.raises(ValueError):
            post_webhook(url, b"{}")
        resolve.assert_not_called()


def test_redirect_is_not_followed_and_proxy_environment_is_ignored(monkeypatch):
    paths = []

    class Target(BaseHTTPRequestHandler):
        def do_POST(self):
            paths.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/secret")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Target)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HTTP_PROXY", "http://169.254.169.254:80")
    try:
        with pytest.raises(ValueError, match="no redirect"):
            post_webhook(f"http://127.0.0.1:{server.server_port}/hook", b"{}")
        assert paths == ["/hook"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_dns_rebinding_does_not_trigger_second_resolution():
    class Socket:
        def settimeout(self, value):
            pass

        def connect(self, address):
            assert address == ("8.8.8.8", 443)

        def close(self):
            pass

    with (
        patch(
            "socket.getaddrinfo",
            return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
        ) as dns,
        patch("socket.socket", return_value=Socket()),
        patch("ssl.create_default_context") as tls,
        patch("http.client.HTTPConnection") as http,
    ):
        http.return_value.getresponse.return_value.status = 204
        post_webhook("https://approved.example/hook", b"{}")
        assert dns.call_count == 1
        tls.return_value.wrap_socket.assert_called_once()
        assert (
            tls.return_value.wrap_socket.call_args.kwargs["server_hostname"] == "approved.example"
        )
