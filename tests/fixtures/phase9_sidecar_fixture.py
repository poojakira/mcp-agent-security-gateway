"""Synthetic internal network sidecar, NOT a secure egress HTTP proxy.

It only answers local health requests; it never forwards external traffic.
"""

from __future__ import annotations

import socket


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 3128))
        server.listen(8)
        while True:
            conn, _ = server.accept()
            with conn:
                conn.settimeout(2.0)
                conn.recv(1024)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")


if __name__ == "__main__":
    main()
