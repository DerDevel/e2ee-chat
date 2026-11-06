#!/usr/bin/env python3
"""End-to-end smoke test for e2ee-chat.

Boots a minimal fake Redis (stdlib, RESP2), the real server binary and two
real client binaries in pseudo-terminals, then drives the full user flow:
nicknames, room creation, /join, accept, SAS comparison, chat in both
directions, and a full re-pair after one side leaves.

The repository root is derived from this script's location; every executed
path is a fixed constant relative to it.
Requires: go, openssl.
"""

import fcntl
import os
import pty
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import termios
import threading
import time

REDIS_PORT = 6399
SRV_PORT = 50099
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class FakeRedis(threading.Thread):
    """Just enough RESP2 for the relay: PING, SET NX EX, GET, DEL."""

    def __init__(self):
        super().__init__(daemon=True)
        self.store = {}
        self.lsock = socket.socket()
        self.lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lsock.bind(("127.0.0.1", REDIS_PORT))
        self.lsock.listen(8)

    def run(self):
        while True:
            c, _ = self.lsock.accept()
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
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
                    # RESP array of bulk strings.
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
                if cmd == b"HELLO":
                    # Force go-redis onto RESP2.
                    c.sendall(b"-ERR unknown command 'HELLO'\r\n")
                elif cmd == b"CLIENT":
                    c.sendall(b"+OK\r\n")
                elif cmd == b"PING":
                    c.sendall(b"+PONG\r\n")
                elif cmd == b"SET":
                    key, val = parts[1], parts[2]
                    nx = any(o.upper() == b"NX" for o in parts[3:])
                    if nx and key in self.store:
                        c.sendall(b"$-1\r\n")  # nil -> SetNX false
                    else:
                        self.store[key] = val
                        c.sendall(b"+OK\r\n")
                elif cmd == b"GET":
                    v = self.store.get(parts[1])
                    if v is None:
                        c.sendall(b"$-1\r\n")
                    else:
                        c.sendall(b"$%d\r\n%s\r\n" % (len(v), v))
                elif cmd == b"DEL":
                    self.store.pop(parts[1], None)
                    c.sendall(b":1\r\n")
                else:
                    c.sendall(b"-ERR unknown command\r\n")
        except OSError:
            pass
        finally:
            try:
                c.close()
            except OSError:
                pass


class Client:
    """A real client binary attached to a pseudo-terminal."""

    def __init__(self, addr, pin, name):
        self.name = name
        self.master, slave = pty.openpty()
        # bubbletea needs a real window size before it renders anything.
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 120, 0, 0))
        env = dict(
            os.environ,
            TERM="xterm-256color",
            E2EE_SERVER_ADDR=addr,
            E2EE_TLS_PIN=pin,
            E2EE_TLS_SERVER_NAME="localhost",
        )
        self.proc = subprocess.Popen(
            ["./client/client"],
            cwd=ROOT,
            stdin=slave,
            stdout=slave,
            stderr=subprocess.DEVNULL,
            env=env,
        )
        os.close(slave)
        self.buf = b""

    def expect(self, needle, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if needle.encode() in self.buf:
                return True
            r, _, _ = select.select([self.master], [], [], 0.2)
            if r:
                try:
                    data = os.read(self.master, 65536)
                except OSError:
                    break
                if data:
                    self.buf += data
        if needle.encode() in self.buf:
            return True
        raise AssertionError(
            f"[{self.name}] timed out waiting for {needle!r}; "
            f"tail: {self.buf[-400:]!r}"
        )

    def send(self, s):
        os.write(self.master, s.encode())

    def safety_code(self):
        pattern = "Код безопасности: ([0-9 ]+)".encode()
        m = re.search(pattern, self.buf)
        if not m:
            raise AssertionError(f"[{self.name}] no safety code in buffer")
        return m.group(1).decode().strip()

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def wait_room(redis_obj, key, timeout=5):
    """Block until the room key is visible in the fake store."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if key.encode() in redis_obj.store:
            return
        time.sleep(0.02)
    raise AssertionError(f"room {key} never appeared in the store")


def cert_pin():
    r = subprocess.run(
        ["openssl", "x509", "-in", "server.crt",
         "-noout", "-fingerprint", "-sha256"],
        capture_output=True, text=True, cwd=ROOT,
    )
    if r.returncode != 0:
        raise AssertionError("pin derivation failed: " + r.stderr)
    for line in r.stdout.splitlines():
        if "=" in line:
            return line.split("=", 1)[1].replace(":", "").lower()
    raise AssertionError("could not derive pin from certificate")


def main():
    print("==> building binaries")
    r = subprocess.run(
        ["go", "build", "-o", "server/server", "./server"],
        capture_output=True, text=True, cwd=ROOT,
    )
    if r.returncode != 0:
        raise AssertionError("server build failed: " + r.stderr)
    r = subprocess.run(
        ["go", "build", "-o", "client/client", "./client"],
        capture_output=True, text=True, cwd=ROOT,
    )
    if r.returncode != 0:
        raise AssertionError("client build failed: " + r.stderr)

    print("==> generating dev certificate")
    r = subprocess.run(
        ["./scripts/gen-certs.sh", "."],
        capture_output=True, text=True, cwd=ROOT,
    )
    if r.returncode != 0:
        raise AssertionError("cert generation failed: " + r.stderr)
    pin = cert_pin()
    assert len(pin) == 64, "unexpected pin length"

    redis = FakeRedis()
    redis.start()

    print("==> starting server")
    srv = subprocess.Popen(
        ["./server/server"],
        cwd=ROOT,
        env=dict(
            os.environ,
            E2EE_LISTEN=f"127.0.0.1:{SRV_PORT}",
            E2EE_REDIS_ADDR=f"127.0.0.1:{REDIS_PORT}",
            E2EE_TLS_CERT="server.crt",
            E2EE_TLS_KEY="server.key",
        ),
        stderr=subprocess.PIPE,
    )
    clients = []
    try:
        time.sleep(1.0)
        if srv.poll() is not None:
            raise AssertionError("server exited: " + srv.stderr.read().decode())

        addr = f"127.0.0.1:{SRV_PORT}"
        print("==> client A creates the room")
        alice = Client(addr, pin, "alice")
        clients.append(alice)
        alice.expect("никнейм")
        alice.send("Alice\r")
        alice.expect("Кодовое слово")
        alice.send("smoke-room-1\r")
        alice.expect("Ожидание подключения")

        print("==> client B joins")
        bob = Client(addr, pin, "bob")
        clients.append(bob)
        bob.expect("никнейм")
        bob.send("Bob\r")
        bob.expect("Кодовое слово")
        bob.send("/join smoke-room-1\r")

        print("==> A accepts")
        alice.expect("Разрешить подключение")
        alice.send("y\r")

        print("==> both paired; comparing SAS")
        alice.expect("Код безопасности")
        bob.expect("Код безопасности")
        ca, cb = alice.safety_code(), bob.safety_code()
        assert ca == cb, f"SAS mismatch: {ca} vs {cb}"
        print(f"    SAS match: {ca}")

        print("==> chat both ways (UTF-8)")
        alice.expect("[Alice]")  # prompt is up
        bob.expect("[Bob]")
        alice.send("привет, Боб!\r")
        bob.expect("привет, Боб!")
        bob.send("и тебе привет\r")
        alice.expect("и тебе привет")

        print("==> B leaves; A must re-pair with fresh keys")
        bob.stop()
        alice.expect("Собеседник отключился")
        alice.buf = b""  # round-2 assertions must not match round-1 output
        alice.send("smoke-room-2\r")  # straight to a new room, same process
        alice.expect("Ожидание подключения")
        wait_room(redis, "room:smoke-room-2")

        carol = Client(addr, pin, "carol")
        clients.append(carol)
        carol.expect("никнейм")
        carol.send("Carol\r")
        carol.expect("Кодовое слово")
        carol.send("/join smoke-room-2\r")
        alice.expect("Разрешить подключение")
        alice.send("y\r")
        alice.expect("Код безопасности")
        carol.expect("Код безопасности")
        assert alice.safety_code() == carol.safety_code(), "re-pair SAS mismatch"
        print(f"    re-pair SAS match: {alice.safety_code()}")

        alice.send("второй раунд\r")
        carol.expect("второй раунд")

        print("\nALL SMOKE CHECKS PASSED")
    finally:
        for c in clients:
            c.stop()
        srv.send_signal(signal.SIGTERM)
        try:
            srv.wait(5)
        except subprocess.TimeoutExpired:
            srv.kill()


if __name__ == "__main__":
    main()
