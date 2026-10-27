#!/usr/bin/env python3
"""build a known-good x86-64 elf quine and optionally submit it to the judge."""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent


def build(size: int) -> bytes:
    sys.path.insert(0, str(ROOT))
    import build as builders  # noqa: WPS433

    if size not in builders.BUILDERS:
        raise SystemExit(f'unknown size {size}; have {sorted(builders.BUILDERS)}')
    data = builders.BUILDERS[size]()
    assert len(data) == size
    return data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--size', type=int, default=104,
                    help='quine size (104/112/120/146 for elf64)')
    ap.add_argument('--out', type=pathlib.Path, default=ROOT / 'quine')
    ap.add_argument('--submit', action='store_true')
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--port', type=int, default=31903)
    args = ap.parse_args()

    data = build(args.size)
    args.out.write_bytes(data)
    args.out.chmod(0o755)
    print(f'wrote {args.out} ({len(data)} bytes)', flush=True)

    if args.submit:
        return subprocess.call(
            [sys.executable, str(HERE / 'submit.py'), str(args.out),
             '--host', args.host, '--port', str(args.port)]
        )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
