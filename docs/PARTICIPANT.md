# challenge: elves can be spooky too

the elves left you a very small doorway.

you are given a host, a port, and a byte budget. send an **x86-64 linux elf**
that:

1. is at most **112 bytes** (the service prints the live limit on connect),
2. writes its **own exact bytes** to stdout,
3. exits with status **0**.

do that and the service hands you the flag.

# access

```text
host: <HOST>
port: 31903
```

# protocol

1. connect (nc, a script, whatever).
2. read the banner.
3. send a line: `SIZE <n>`
4. send exactly `<n>` raw bytes (your elf).
5. read the reply: `PASS ...` / `FLAG ...` or `FAIL ...`.

example:

```bash
python3 - <<'PY'
import socket, pathlib, sys
host, port = sys.argv[1], int(sys.argv[2])
img = pathlib.Path(sys.argv[3]).read_bytes()
s = socket.create_connection((host, port))
banner = b''
while not banner.endswith(b'\n\n'):
    banner += s.recv(4096)
print(banner.decode(), end='')
s.sendall(f'SIZE {len(img)}\n'.encode() + img)
print(s.recv(4096).decode(), end='')
PY
# usage: python3 script.py <HOST> 31903 ./myquine
```

# hints

- `#!/bin/cat` is clever but it is not a standalone executable. investigate the elf standard.
- the kernel is picky about some header fields, others not so much. 
- your binary is run once, output needs to be the same as the input, exit status = 0.
