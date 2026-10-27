"""build known-good self-replicating ELFs for this challenge (organizer tool).

each entry in BUILDERS is one size milestone. for the default x86-64 judge,
104 / 112 / 120 / 146 are the ones that matter. the elf32 line is here if you
open REQUIRE_X86_64. usage:

    python3 build.py 104        # write ./quine at that size
    python3 build.py all        # write versions/quine_<size> for every version

verify with ./validate.py. see docs/ORGANIZER.md for which tricks each size uses.
"""
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).parent


# --- ELF64 line (portable: valid 64-bit header) -----------------------------

def elf64_146():
    """Textbook layout: 64B ehdr + 56B phdr + 26B code, zero overlap."""
    BASE = 0x400000
    code = bytearray.fromhex(
        '488d3500000000'            # lea rsi,[rip+disp32]
        'ba00000000'                # mov edx, size
        '6a015f' '6a0158' '0f05'    # rdi=1, rax=1, syscall (write)
        'b03c' '31ff' '0f05')       # al=60, edi=0, syscall (exit)
    size = 64 + 56 + len(code)
    struct.pack_into('<i', code, 3, -(120 + 7))
    struct.pack_into('<I', code, 8, size)
    eh = struct.pack('<16sHHIQQQIHHHHHH',
                     b'\x7fELF\x02\x01\x01' + bytes(9), 2, 62, 1,
                     BASE + 120, 64, 0, 0, 64, 56, 1, 0, 0, 0)
    ph = struct.pack('<IIQQQQQQ', 1, 5, 0, BASE, BASE, size, size, 0x1000)
    return eh + ph + code


def _elf64(size, phoff):
    """Shared ELF header for the 112/104 variants: frag A in e_ident jumping
    to frag B in p_paddr, frag C (write + exit) in e_shoff."""
    BASE = 0x10000
    b = bytearray(size)
    b[0:7] = b'\x7fELF\x02\x01\x01'
    # frag A @0x07: rsi=BASE, dl=size, jmp to frag B (in p_paddr)
    rel_a = (phoff + 0x18) - 0x10
    b[0x07:0x10] = bytes.fromhex(
        'be' + BASE.to_bytes(4, 'little').hex() + 'b2%02x' % size +
        'eb%02x' % (rel_a & 0xff))
    struct.pack_into('<HHI', b, 0x10, 2, 62, 1)
    struct.pack_into('<Q', b, 0x18, BASE + 0x07)
    struct.pack_into('<Q', b, 0x20, phoff)
    # frag C @0x28 (in e_shoff): write + exit
    b[0x28:0x30] = bytes.fromhex('0f05' 'b03c' '31ff' '0f05')
    struct.pack_into('<H', b, 0x36, 56)                    # e_phentsize
    return BASE, b


def elf64_120():
    """phoff=0x38; e_phnum reused as p_type low byte. Code tail appended."""
    BASE = 0x10000
    size, phoff = 0x78, 0x38
    b = bytearray(size)
    b[0:7] = b'\x7fELF\x02\x01\x01'
    b[0x07:0x10] = bytes.fromhex(
        'be' + BASE.to_bytes(4, 'little').hex() + 'b2%02x' % size + 'eb40')
    struct.pack_into('<HHI', b, 0x10, 2, 62, 1)
    struct.pack_into('<Q', b, 0x18, BASE + 0x07)
    struct.pack_into('<Q', b, 0x20, phoff)
    struct.pack_into('<H', b, 0x36, 56)
    struct.pack_into('<II', b, phoff + 0x00, 1, 5)        # p_type, p_flags
    struct.pack_into('<Q', b, phoff + 0x08, 0)            # p_offset
    struct.pack_into('<Q', b, phoff + 0x10, BASE)         # p_vaddr
    b[phoff + 0x18:phoff + 0x20] = bytes.fromhex('6a015f' '6a0158' 'eb18')
    struct.pack_into('<Q', b, phoff + 0x20, size)         # p_filesz
    struct.pack_into('<Q', b, phoff + 0x28, size)         # p_memsz
    struct.pack_into('<Q', b, phoff + 0x30, 0x1000)       # p_align
    b[0x70:0x78] = bytes.fromhex('0f05' 'b03c' '31ff' '0f05')
    return bytes(b)


def elf64_112():
    """Same as 120 but write+exit hidden in e_shoff; no appended tail."""
    size, phoff = 0x70, 0x38
    BASE, b = _elf64(size, phoff)
    struct.pack_into('<II', b, phoff + 0x00, 1, 5)
    struct.pack_into('<Q', b, phoff + 0x08, 0)
    struct.pack_into('<Q', b, phoff + 0x10, BASE)
    b[phoff + 0x18:phoff + 0x20] = bytes.fromhex('6a015f' '6a0158' 'ebd0')
    struct.pack_into('<Q', b, phoff + 0x20, size)
    struct.pack_into('<Q', b, phoff + 0x28, size)
    struct.pack_into('<Q', b, phoff + 0x30, 0x1000)
    return bytes(b)


def elf64_104():
    """phoff slid to 0x30: e_phentsize folds into p_flags high bytes,
    e_phnum into p_offset low byte (p_offset=1, p_vaddr=BASE+1)."""
    size, phoff = 0x68, 0x30
    BASE, b = _elf64(size, phoff)
    struct.pack_into('<I', b, phoff + 0x00, 1)            # p_type (e_flags)
    struct.pack_into('<I', b, phoff + 0x04, 0x380005)     # p_flags hi=56
    struct.pack_into('<Q', b, phoff + 0x08, 1)            # p_offset=1 (e_phnum)
    struct.pack_into('<Q', b, phoff + 0x10, BASE + 1)     # p_vaddr
    b[phoff + 0x18:phoff + 0x20] = bytes.fromhex('6a015f' '6a0158' 'ebd8')
    struct.pack_into('<Q', b, phoff + 0x20, size - 1)     # p_filesz
    struct.pack_into('<Q', b, phoff + 0x28, size - 1)     # p_memsz
    struct.pack_into('<Q', b, phoff + 0x30, 0x1000)       # p_align
    return bytes(b)


# --- ELF32 line (via IA32 compat; much smaller headers) ---------------------

def _elf32(size, code_start, code_hex, pad_flags=True):
    """phoff=0x20 overlapping the ELF header. e_phentsize(=32) rides in the
    high bytes of p_vaddr (BASE=0x200000), e_phnum(=1) in p_paddr low word.
    frag A lives in e_ident (0x07) and jumps to code_start, which runs through
    p_flags-high / p_align / appended bytes to the end. pad_flags=False leaves
    p_flags' high bytes free for code (the kernel only reads bits 0-2)."""
    BASE, P = 0x200000, 0x20
    b = bytearray(size)
    b[0:7] = b'\x7fELF\x01\x01\x01'
    rel = code_start - 0x10
    b[0x07:0x10] = bytes.fromhex(
        'b9' + BASE.to_bytes(4, 'little').hex() + 'b2%02x' % size +
        'eb%02x' % (rel & 0xff))
    struct.pack_into('<HHI', b, 0x10, 2, 3, 1)            # ET_EXEC, EM_386, ver
    struct.pack_into('<I', b, 0x18, BASE + 0x07)          # e_entry
    struct.pack_into('<I', b, 0x1c, P)                    # e_phoff
    struct.pack_into('<I', b, P + 0x00, 1)               # p_type
    struct.pack_into('<I', b, P + 0x04, 0)              # p_offset
    struct.pack_into('<I', b, P + 0x08, BASE)          # p_vaddr (0x2a=32)
    struct.pack_into('<I', b, P + 0x0c, 1)             # p_paddr lo=e_phnum
    struct.pack_into('<I', b, P + 0x10, size)          # p_filesz
    struct.pack_into('<I', b, P + 0x14, size)          # p_memsz
    if pad_flags:
        struct.pack_into('<I', b, P + 0x18, 5)         # full p_flags
    else:
        b[P + 0x18] = 5                                # only low byte matters
    if code_start >= P + 0x20:
        struct.pack_into('<I', b, P + 0x1c, 0x1000)    # p_align not reused
    b[code_start:code_start + len(code_hex) // 2] = bytes.fromhex(code_hex)
    return bytes(b)


def elf32_79():
    """First ELF32 cut: tail at 0x40, full-width write/exit via push/pop."""
    return _elf32(0x4f, 0x40, '6a015b' '6a0458' 'cd80' '6a0158' '31db' 'cd80')


def elf32_77():
    """Reuse eax/ebx left by write's return for the exit call."""
    return _elf32(0x4d, 0x40, '6a015b' '6a0458' 'cd80' 'b001' '4b' 'cd80')


def elf32_73():
    """Overwrite p_align with code and fall through into the tail (one jump)."""
    return _elf32(0x49, 0x3c, '6a015b' '6a0458' 'cd80' 'b001' '4b' 'cd80')


def elf32_70():
    """Start code at 0x39: p_flags high bytes are ignored too."""
    return _elf32(0x46, 0x39, '6a015b' '6a0458' 'cd80' 'b001' '4b' 'cd80',
                  pad_flags=False)


def elf32_68():
    """Assume eax/ebx are zero at entry (true on this kernel): mov bl/al."""
    return _elf32(0x44, 0x39, 'b301' 'b004' 'cd80' 'b001' '4b' 'cd80',
                  pad_flags=False)


def elf32_64():
    """Hard floor (= phdr size at phoff 0x20). Every trick at once:
    - e_version (0x14, unchecked) holds code.
    - p_flags low byte is 0xcd and the next byte 0x80, so the bytes `cd 80`
      ARE the write `int 0x80` while still granting R (0xcd & PF_R) + X.
    - the load address is built with `bts ecx, 21` (ecx=0 at entry).
    - ecx/ebx/eax are assumed zero at entry.
    """
    BASE, P, size = 0x200000, 0x20, 0x40
    b = bytearray(size)
    b[0:7] = b'\x7fELF\x01\x01\x01'
    # frag A @0x07: bts ecx,21 (ecx=BASE); mov dl,size; inc ebx (ebx=1); jmp 0x14
    b[0x07:0x10] = bytes.fromhex('0fbae915' 'b2%02x' % size + '43' 'eb04')
    struct.pack_into('<HH', b, 0x10, 2, 3)               # e_type, e_machine
    # e_version @0x14 (unchecked): mov al,4 (write nr); jmp 0x38
    b[0x14:0x18] = bytes.fromhex('b004' 'eb20')
    struct.pack_into('<I', b, 0x18, BASE + 0x07)          # e_entry
    struct.pack_into('<I', b, 0x1c, P)                    # e_phoff
    struct.pack_into('<IIIIII', b, P, 1, 0, BASE, 1, size, size)
    # p_flags @0x38: low bytes cd 80 == `int 0x80` (write); R+X bits still set.
    # falls through p_align: mov al,1; dec ebx; int 0x80 (exit).
    b[0x38:0x3f] = bytes.fromhex('cd80' 'b001' '4b' 'cd80')
    return bytes(b)


def elf32_53():
    """Champion. e_phoff=4, so the 32-byte phdr overlaps almost the entire ELF
    header (0x04-0x24):
    - p_type (0x04) IS the valid EI_CLASS/DATA/VERSION/OSABI bytes (01 00 00 00).
    - p_paddr (0x10) IS e_type=2 + e_machine=3.
    - p_filesz/p_memsz ARE e_version / e_entry; p_flags (0x1c) IS e_phoff=4
      (PF_R only; the 32-bit compat loader runs R pages via READ_IMPLIES_EXEC).
    - p_align (0x20) is the entry code.
    The mandatory e_phentsize/e_phnum sit just past the phdr and are swallowed as
    the imm32 of a junk `mov edi`. Assumes ecx/ebx/eax zero at entry.
    """
    BASE, size = 0x10000, 0x35
    b = bytearray(size)
    b[0:4] = b'\x7fELF'
    struct.pack_into('<I', b, 0x04, 1)                    # p_type / EI_CLASS=1
    struct.pack_into('<I', b, 0x08, 0)                    # p_offset / EI pad
    struct.pack_into('<I', b, 0x0c, BASE)                 # p_vaddr
    struct.pack_into('<HH', b, 0x10, 2, 3)               # e_type/e_machine (p_paddr)
    struct.pack_into('<I', b, 0x14, 0x1000)              # e_version (p_filesz)
    struct.pack_into('<I', b, 0x18, BASE + 0x20)         # e_entry (p_memsz)
    struct.pack_into('<I', b, 0x1c, 4)                   # e_phoff=4 (p_flags, PF_R)
    # entry @0x20 (= p_align): ecx=BASE via bts; dl=size; ebx=1; al=4 (write nr)
    b[0x20:0x29] = bytes.fromhex('0fbae910' 'b2%02x' % size + '43' 'b004')
    b[0x29] = 0xbf                                         # mov edi, imm32 ...
    struct.pack_into('<HH', b, 0x2a, 32, 1)             # ...imm = e_phentsize,e_phnum
    b[0x2e:0x35] = bytes.fromhex('cd80' 'b001' '4b' 'cd80')  # write; exit
    return bytes(b)


BUILDERS = {
    146: elf64_146, 120: elf64_120, 112: elf64_112, 104: elf64_104,
    79: elf32_79, 77: elf32_77, 73: elf32_73, 70: elf32_70, 68: elf32_68,
    64: elf32_64, 53: elf32_53,
}
DEFAULT = 104  # elf64 floor; matches the intended x86-64 challenge line


def write(path, data):
    path.write_bytes(data)
    path.chmod(0o755)


def main(argv):
    arg = argv[1] if len(argv) > 1 else str(DEFAULT)
    if arg == 'all':
        out = HERE / 'versions'
        out.mkdir(exist_ok=True)
        for size, fn in sorted(BUILDERS.items()):
            data = fn()
            assert len(data) == size, (size, len(data))
            write(out / f'quine_{size}', data)
            print(f'versions/quine_{size} ({size} bytes)')
        return 0
    size = int(arg)
    if size not in BUILDERS:
        print(f'unknown version {size}; have {sorted(BUILDERS)}')
        return 1
    data = BUILDERS[size]()
    assert len(data) == size, (size, len(data))
    write(HERE / 'quine', data)
    print(f'Wrote quine ({size} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
