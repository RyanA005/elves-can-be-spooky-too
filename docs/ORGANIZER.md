# organizer notes

participants connect to a tcp judge and upload a tiny x86-64 linux elf. if the
binary prints itself and exits 0 under the byte limit, they get the flag.

the intended insight is that linux does not check every elf / program header
field. you can overlap the program header into the elf header and hide
instructions in the fields the loader ignores (`e_shoff`, `p_paddr`, most of
`e_ident`, high bits of `p_flags`, etc).

# how it works

- `server.py` accepts one submission per connection.
- client sends `SIZE <n>\n` then `<n>` raw bytes.
- `validate.py` checks the size, elf magic, optional x86-64 class/machine,
  runs the binary with a short timeout and empty env, and compares stdout to
  the submitted image.
- on success the server prints `FLAG <flag>`.

**important:** the judge executes attacker machine code. run it in a disposable
container/vm with no credentials and no lateral network. the provided
`compose.yaml` drops caps, runs read-only as uid 10001, and uses a tmpfs for
`/tmp`. harden further (gvisor / firecracker / nsjail) if you need to.

# difficulty dial

`BYTE_LIMIT` (default **112**) is the main knob. `REQUIRE_X86_64=1` by default.

| limit | what it forces |
|------:|----------------|
| 146+  | textbook elf64, almost no header tricks |
| 120   | must overlap the program header into the elf header |
| **112** (default) | also hide code in ignored fields |
| 104   | elf64 floor on this kernel (all the overlap tricks) |
| ~80   | impossible for elf64 here. set `REQUIRE_X86_64=0` / `--allow-any-arch` and the elf32 builders in `build.py` fit (70 is the robust elf32 default) |

recommended spookyctf setting: **112**, x86-64 only.

# solution (spoiler)

`build.py` can emit known-good quines. the default challenge wants elf64:

```bash
python3 build.py 104          # writes ./quine
python3 validate.py quine --limit 112
python3 tools/solve.py --size 104 --submit --port 31903
```

sizes that matter for the default config:

| bytes | idea |
|------:|------|
| 146 | textbook: 64B ehdr + 56B phdr + code, no overlap |
| 120 | `e_phoff=0x38`, phdr overlaps the elf header |
| 112 | write+exit stashed in `e_shoff`, fragment in `p_paddr` |
| 104 | phdr at `0x30`; `e_phentsize` / `e_phnum` dual-use with phdr fields |

code is just `write(1, mapped_image, size)` then `exit(0)` via raw syscalls.
`rdx` is 0 at entry for a static elf so `mov dl, size` is enough for the length.

assumptions that hold on a normal x86-64 linux (including the docker image):

- `vm.mmap_min_addr` allows load at `0x10000` (default)
- static entry leaves `rdx == 0`

elf32 variants down to 53 bytes are also in `build.py` if you ever open the
arch restriction. they need `CONFIG_IA32_EMULATION` and get more
kernel-specific as they shrink.

# run (dev)

```bash
python3 server.py --port 31903 --limit 112
python3 tools/solve.py --size 104 --submit --port 31903
```

development flag is `spooky{phdr_in_ehdr_c2d021cc4fc5}` in `flag.txt`.

# deploy

put the real flag in `flag.txt` or set `FLAG` before bringing the service up.

```bash
FLAG='spooky{phdr_in_ehdr_c2d021cc4fc5}' BYTE_LIMIT=112 docker compose up --build -d
```

publish port 31903. fill in `<HOST>` in the participant handout.

# participant handout

ship `docs/PARTICIPANT.md` (with the real host). do **not** ship `build.py`,
`tools/solve.py`, or this file to players. `tools/submit.py` is fine to give
them as a convenience, or let them write their own from the protocol blurb.

# checks

- `python3 tools/solve.py --size 104 --submit` returns PASS + FLAG against a
  live server on the configured limit.
- `python3 validate.py` rejects `#!/bin/cat`, rejects a 146-byte textbook elf
  when the limit is 112, and rejects elf32 when `REQUIRE_X86_64=1`.
- the container env flag is the production flag, not the development one.
