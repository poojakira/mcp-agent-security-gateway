"""Synthetic internal-network health sidecar; never forwards external traffic.

This fixture is launched only on a disposable Docker --internal bridge.
Bind its container-assigned private IPv4 address rather than every interface,
and fail closed if Docker's network address cannot be established.
"""

from __future__ import annotations

import ipaddress
import socket


def _container_bind_address() -> str:
    """Resolve the container interface without falling back to a wildcard bind."""
    resolved = socket.gethostbyname(socket.gethostname())
    address = ipaddress.ip_address(resolved)
    if (
        not isinstance(address, ipaddress.IPv4Address)
        or not address.is_private
        or address.is_loopback
        or address.is_unspecified
    ):
        raise RuntimeError("Synthetic sidecar requires a private container IPv4 address")
    return resolved


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((_container_bind_address(), 3128))
        server.listen(8)
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(2.0)
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")


if __name__ == "__main__":
    main()
