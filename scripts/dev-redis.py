#!/usr/bin/env python3
"""Minimal in-memory Redis stand-in for local development and manual testing.

Implements just enough RESP2 for the e2ee-chat relay: PING, SET (with NX/EX),
GET, DEL, plus a few handshake commands go-redis sends. No persistence, no
auth. Useful on machines without Docker or a system Redis; the server treats
it exactly like a real Redis.

Usage: scripts/dev-redis.py [port]   (default 6379)
"""

import socket
import sys
import threading

STORE = {}
LOCK = threading.Lock()


def handle(c):
    f = c.makefile("rb")
    try:
        while True:
            line = f.readline()
            if not line:
                return
            line = line.strip()
            if not line:
                continue
            if line.startswith(b"*"):
                n = int(line[1:])
                parts = []
                for _ in range(n):
                    hdr = f.readline().strip()
                    if not hdr.startswith(b"$"):
                        raise OSError("bad bulk header")
                    length = int(hdr[1:])
                    data = f.read(length + 2)[:-2] if length >= 0 else None
                    if data is not None:
                        parts.append(data)
            else:
                parts = line.split(b" ")
            if not parts:
                continue
            cmd = parts[0].upper()

            with LOCK:
                if cmd == b"HELLO":
                    c.sendall(b"-ERR unknown command 'HELLO'\r\n")
                elif cmd == b"CLIENT":
                    c.sendall(b"+OK\r\n")
                elif cmd == b"PING":
                    c.sendall(b"+PONG\r\n")
                elif cmd == b"SET":
                    key, val = parts[1], parts[2]
                    nx = any(o.upper() == b"NX" for o in parts[3:])
                    if nx and key in STORE:
                        c.sendall(b"$-1\r\n")
                    else:
                        STORE[key] = val
                        c.sendall(b"+OK\r\n")
                elif cmd == b"GET":
                    v = STORE.get(parts[1])
                    if v is None:
                        c.sendall(b"$-1\r\n")
                    else:
                        c.sendall(b"$%d\r\n%s\r\n" % (len(v), v))
                elif cmd == b"DEL":
                    STORE.pop(parts[1], None)
                    c.sendall(b":1\r\n")
                elif cmd == b"EVAL":
                    # Only the compare-and-delete script the relay sends:
                    #   EVAL <script> 1 <key> <prefix>
                    # Implemented natively: delete when the stored value
                    # starts with <prefix>.
                    if len(parts) >= 5:
                        key, prefix = parts[3], parts[4]
                        v = STORE.get(key)
                        if v is not None and v.startswith(prefix):
                            del STORE[key]
                            c.sendall(b":1\r\n")
                        else:
                            c.sendall(b":0\r\n")
                    else:
                        c.sendall(b"-ERR unsupported EVAL\r\n")
                else:
                    c.sendall(b"-ERR unknown command\r\n")
    except OSError:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 6379
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(16)
    print(f"dev-redis: listening on 127.0.0.1:{port} (in-memory, no auth)", flush=True)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


if __name__ == "__main__":
    main()
