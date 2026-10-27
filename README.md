# elves can be spooky too

size-constrained x86-64 ELF quine challenge for spookyctf.

participants get a host, a port, and a byte limit. they send a linux elf that
prints its own exact bytes and exits 0. a normal elf will not fit, so they have
to find which header fields the kernel actually checks and which ones they can
stuff code into.

participant info: [docs/PARTICIPANT.md](docs/PARTICIPANT.md)

organizer info: [docs/ORGANIZER.md](docs/ORGANIZER.md)

## run

```bash
python3 server.py --port 31903 --limit 112
```

development flag is `spooky{phdr_in_ehdr_c2d021cc4fc5}` from `flag.txt`. override with
`FLAG` or `--flag`.

```bash
python3 build.py 104
python3 tools/submit.py quine --host 127.0.0.1 --port 31903
```

or the one-liner that builds and submits:

```bash
python3 tools/solve.py --size 104 --submit --port 31903
```

## docker

```bash
docker compose up --build
```

publishes port 31903. set `FLAG` / `BYTE_LIMIT` in `compose.yaml` (or the
environment) before a real event.
