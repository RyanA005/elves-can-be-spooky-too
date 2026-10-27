#!/usr/bin/env python3
"""submit a local elf to the challenge server and print the response."""
from __future__ import annotations

import argparse
import pathlib
import socket
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('path', type=pathlib.Path)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=31903)
    args = ap.parse_args()

    image = args.path.read_bytes()
    with socket.create_connection((args.host, args.port), timeout=10) as sock:
        banner = b''
        while not banner.endswith(b'\n\n'):
            chunk = sock.recv(4096)
            if not chunk:
                break
            banner += chunk
        sys.stdout.buffer.write(banner)

        sock.sendall(f'SIZE {len(image)}\n'.encode('ascii'))
        sock.sendall(image)

        resp = b''
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
        sys.stdout.buffer.write(resp)
        return 0 if resp.startswith(b'PASS') else 1


if __name__ == '__main__':
    raise SystemExit(main())
