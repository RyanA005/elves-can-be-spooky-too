#!/usr/bin/env python3
"""tcp judge for elves can be spooky too.

one shot per connection:
  1. server sends a short text banner ending with a blank line
  2. client sends: SIZE <n>\\n followed by exactly <n> raw bytes
  3. server replies PASS/FLAG or FAIL

env: FLAG, BYTE_LIMIT (default 112), BIND_HOST, BIND_PORT (31903),
     RUN_TIMEOUT (2), REQUIRE_X86_64 (1)
"""
from __future__ import annotations

import argparse
import os
import pathlib
import socket
import socketserver
import traceback

from validate import validate_image


HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_LIMIT = 112
DEFAULT_PORT = 31903


def load_flag(explicit: str | None) -> str:
    if explicit:
        return explicit.strip()
    env = os.environ.get('FLAG')
    if env:
        return env.strip()
    path = HERE / 'flag.txt'
    if path.is_file():
        return path.read_text(encoding='utf-8').strip()
    return 'spooky{phdr_in_ehdr_c2d021cc4fc5}'


def banner(limit: int) -> bytes:
    lines = [
        'elves can be spooky too',
        '',
        'send an x86-64 linux elf that prints its own exact bytes to stdout',
        'and exits 0. a textbook elf will not fit. abuse the header fields',
        'the kernel ignores.',
        '',
        f'byte limit: {limit}',
        '',
        'protocol: send  SIZE <n>  then a newline, then exactly <n> bytes.',
        '',
    ]
    return '\n'.join(lines).encode('ascii') + b'\n'


def read_exact(sock: socket.socket, n: int, *, overall_limit: int) -> bytes:
    """Read exactly n bytes, rejecting absurd sizes early."""
    if n < 0 or n > overall_limit:
        raise ValueError(f'SIZE out of range (0..{overall_limit})')
    chunks: list[bytes] = []
    got = 0
    while got < n:
        chunk = sock.recv(min(4096, n - got))
        if not chunk:
            raise ValueError(f'short read ({got}/{n})')
        chunks.append(chunk)
        got += len(chunk)
    return b''.join(chunks)


def read_line(sock: socket.socket, *, max_len: int = 64) -> str:
    buf = bytearray()
    while True:
        if len(buf) > max_len:
            raise ValueError('line too long')
        b = sock.recv(1)
        if not b:
            raise ValueError('connection closed while reading line')
        if b == b'\n':
            break
        if b == b'\r':
            continue
        buf += b
    return buf.decode('ascii', errors='strict')


def handle_client(
    sock: socket.socket,
    *,
    limit: int,
    timeout: float,
    require_x86_64: bool,
    flag: str,
) -> None:
    sock.settimeout(10.0)
    sock.sendall(banner(limit))

    # Accept one extra byte on the wire so we can report "over limit"
    # distinctly from a protocol error, but never execute oversize images.
    wire_cap = limit + 1

    line = read_line(sock)
    parts = line.strip().split()
    if len(parts) != 2 or parts[0].upper() != 'SIZE' or not parts[1].isdigit():
        sock.sendall(b'FAIL send SIZE <n> then the bytes\n')
        return

    n = int(parts[1])
    if n > wire_cap:
        sock.sendall(f'FAIL SIZE {n} > {limit} byte limit\n'.encode('ascii'))
        return

    image = read_exact(sock, n, overall_limit=wire_cap)
    result = validate_image(
        image,
        limit=limit,
        timeout=timeout,
        require_x86_64=require_x86_64,
    )
    if result.ok:
        sock.sendall(f'PASS {result.message}\nFLAG {flag}\n'.encode('utf-8'))
    else:
        sock.sendall(f'FAIL {result.message}\n'.encode('utf-8'))


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_handler(limit, timeout, require_x86_64, flag):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            peer = self.client_address
            try:
                handle_client(
                    self.request,
                    limit=limit,
                    timeout=timeout,
                    require_x86_64=require_x86_64,
                    flag=flag,
                )
            except (ValueError, TimeoutError, socket.timeout) as exc:
                try:
                    self.request.sendall(f'FAIL {exc}\n'.encode('ascii'))
                except OSError:
                    pass
            except Exception:
                traceback.print_exc()
                try:
                    self.request.sendall(b'FAIL internal error\n')
                except OSError:
                    pass
            finally:
                print(f'[+] done {peer}', flush=True)

    return Handler


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--host', default=os.environ.get('BIND_HOST', '0.0.0.0'))
    ap.add_argument('--port', type=int,
                    default=int(os.environ.get('BIND_PORT', str(DEFAULT_PORT))))
    ap.add_argument('--limit', type=int,
                    default=int(os.environ.get('BYTE_LIMIT', str(DEFAULT_LIMIT))),
                    help='max ELF size in bytes (default 112; floor for '
                         'ELF64 quines on Linux is 104)')
    ap.add_argument('--timeout', type=float,
                    default=float(os.environ.get('RUN_TIMEOUT', '2')))
    ap.add_argument('--flag', default=None)
    ap.add_argument('--allow-any-arch', action='store_true',
                    help='accept non-x86-64 ELFs (e.g. ELF32 for an ~80B limit)')
    args = ap.parse_args(argv)

    require_x86_64 = not args.allow_any_arch
    if 'REQUIRE_X86_64' in os.environ:
        require_x86_64 = os.environ['REQUIRE_X86_64'] not in ('0', 'false', 'no')

    flag = load_flag(args.flag)
    handler = make_handler(args.limit, args.timeout, require_x86_64, flag)
    server = ThreadedTCPServer((args.host, args.port), handler)

    arch = 'x86-64 ELF only' if require_x86_64 else 'any ELF arch'
    print(
        f'listening on {args.host}:{args.port}  '
        f'limit={args.limit}  timeout={args.timeout}s  ({arch})',
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nshutting down', flush=True)
    finally:
        server.server_close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
