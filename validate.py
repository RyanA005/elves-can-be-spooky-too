#!/usr/bin/env python3
"""validate an elf quine submission.

checks, in order:
  1. size is within the byte budget
  2. elf magic is present (rejects shebang tricks like #!/bin/cat)
  3. optional x86-64 class/machine constraints
  4. the binary exits 0 within a strict timeout
  5. stdout is byte-for-byte identical to the submitted image

this executes the candidate. only run the judge inside a disposable,
network-isolated container or microvm.

usage: ./validate.py [path] [--limit N] [--timeout S] [--allow-any-arch]
"""
from __future__ import annotations

import os
import pathlib
import struct
import subprocess
import tempfile
from dataclasses import dataclass


ELFCLASS64 = 2
EM_X86_64 = 62


@dataclass(frozen=True)
class Result:
    ok: bool
    message: str


def _require_x86_64(image: bytes) -> Result | None:
    if len(image) < 0x18:
        return Result(False, 'ELF too short to read class/machine')
    ei_class = image[4]
    if ei_class != ELFCLASS64:
        return Result(False, f'EI_CLASS={ei_class} (need ELFCLASS64=2)')
    e_type, e_machine = struct.unpack_from('<HH', image, 0x10)
    if e_machine != EM_X86_64:
        return Result(False, f'e_machine={e_machine} (need EM_X86_64=62)')
    if e_type not in (2, 3):  # ET_EXEC, ET_DYN
        return Result(False, f'e_type={e_type} (need ET_EXEC or ET_DYN)')
    return None


def validate_image(
    image: bytes,
    *,
    limit: int,
    timeout: float = 2.0,
    require_x86_64: bool = True,
) -> Result:
    size = len(image)
    if size == 0:
        return Result(False, 'empty submission')
    if size > limit:
        return Result(False, f'{size} > {limit} byte limit')
    if image[:4] != b'\x7fELF':
        return Result(False, 'not an ELF file (bad magic)')

    if require_x86_64:
        bad = _require_x86_64(image)
        if bad is not None:
            return bad

    with tempfile.TemporaryDirectory(prefix='elf-quine-') as tmp:
        path = pathlib.Path(tmp) / 'submission'
        path.write_bytes(image)
        path.chmod(0o700)
        try:
            proc = subprocess.run(
                [str(path)],
                capture_output=True,
                stdin=subprocess.DEVNULL,
                env={},
                cwd=tmp,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return Result(False, f'did not exit within {timeout}s')
        except OSError as exc:
            return Result(False, f'could not execute: {exc}')

    if proc.returncode != 0:
        return Result(False, f'exit status {proc.returncode} (expected 0)')

    out = proc.stdout
    if out != image:
        detail = f'stdout {len(out)} bytes, file {size} bytes'
        for i, (a, b) in enumerate(zip(out, image)):
            if a != b:
                detail += f'; first diff @ {i}: stdout={a:#04x} file={b:#04x}'
                break
        else:
            if len(out) != size:
                detail += '; lengths differ'
        return Result(False, f'not a quine ({detail})')

    return Result(True, f'exact quine, exit 0, {size} bytes')


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('path', nargs='?', default='quine')
    ap.add_argument('--limit', type=int,
                    default=int(os.environ.get('BYTE_LIMIT', '112')))
    ap.add_argument('--timeout', type=float, default=2.0)
    ap.add_argument('--allow-any-arch', action='store_true',
                    help='do not require ELFCLASS64 / EM_X86_64')
    args = ap.parse_args()

    path = pathlib.Path(args.path)
    if not path.is_file():
        print(f'FAIL: {path} is not a file')
        return 1

    result = validate_image(
        path.read_bytes(),
        limit=args.limit,
        timeout=args.timeout,
        require_x86_64=not args.allow_any_arch,
    )
    print(('PASS: ' if result.ok else 'FAIL: ') + result.message)
    return 0 if result.ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
