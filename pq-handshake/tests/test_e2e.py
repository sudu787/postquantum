"""End-to-end tests: the real server.py and client.py as separate processes
talking over TCP, with an in-test man-in-the-middle proxy for the attacks."""
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

import messages
from conftest import _relay, flip
from messages import APP_DATA, CLIENT_HELLO, FINISHED, SERVER_HELLO

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable
WAIT = 30


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ServerProcess:
    def __init__(self, tmp_path, name="server", timeout=10):
        self.port = _free_port()
        self.pk_path = str(tmp_path / f"{name}_pk.bin")
        self.lines = []
        self._lock = threading.Lock()
        self.proc = subprocess.Popen(
            [PY, "-u", "server.py", "--port", str(self.port), "--pk-out", self.pk_path,
             "--timeout", str(timeout)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        threading.Thread(target=self._read, daemon=True).start()
        self.wait_for("listening")

    def _read(self):
        for line in self.proc.stdout:
            with self._lock:
                self.lines.append(line.rstrip())

    def output(self):
        with self._lock:
            return "\n".join(self.lines)

    def count(self, text):
        with self._lock:
            return sum(text in line for line in self.lines)

    def wait_for(self, text, n=1):
        deadline = time.time() + WAIT
        while time.time() < deadline:
            if self.count(text) >= n:
                return
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        raise AssertionError(f"server never printed {text!r} x{n}:\n{self.output()}")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


@pytest.fixture
def server(tmp_path):
    s = ServerProcess(tmp_path)
    yield s
    s.stop()


def run_client(port, pk_path, message="hello e2e"):
    return subprocess.run(
        [PY, "client.py", "--port", str(port), "--server-pk", pk_path, "--message", message],
        cwd=ROOT, capture_output=True, text=True, timeout=WAIT,
    )


class Proxy:
    """Frame-level MITM between a client and the real server."""

    def __init__(self, upstream_port, tamper=None):
        self.upstream_port = upstream_port
        self.seen = []  # (direction, msg_type, payload) as the proxy received them
        self._tamper = tamper
        self._lsock = socket.create_server(("127.0.0.1", 0))
        self.port = self._lsock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _hook(self, direction):
        def hook(msg_type, payload):
            self.seen.append((direction, msg_type, payload))
            if self._tamper is not None:
                return self._tamper(direction, msg_type, payload)
            return msg_type, payload
        return hook

    def _serve(self):
        while True:
            try:
                down, _ = self._lsock.accept()
            except OSError:
                return
            up = socket.create_connection(("127.0.0.1", self.upstream_port))
            for s in (down, up):
                s.settimeout(WAIT)
            threading.Thread(target=_relay, args=(down, up, self._hook("c2s")), daemon=True).start()
            threading.Thread(target=_relay, args=(up, down, self._hook("s2c")), daemon=True).start()

    def close(self):
        self._lsock.close()


def tamper_once(direction, target_type, mutate):
    def tamper(d, msg_type, payload):
        if d == direction and msg_type == target_type:
            payload = mutate(payload)
        return msg_type, payload
    return tamper


def assert_client_failed(result, reason):
    assert result.returncode != 0, result.stdout
    assert "HandshakeError" in result.stderr, result.stderr
    assert reason in result.stderr, result.stderr
    assert "handshake OK" not in result.stdout


# ---- happy path -----------------------------------------------------------

def test_e2e_handshake_and_encrypted_echo(server):
    r = run_client(server.port, server.pk_path, "hello from Suddu")
    assert r.returncode == 0, r.stderr
    assert "[client] handshake OK" in r.stdout
    assert "reply: server got: hello from Suddu" in r.stdout
    server.wait_for("received: hello from Suddu")


def test_e2e_many_clients_one_server(server):
    for i in range(5):
        r = run_client(server.port, server.pk_path, f"client {i}")
        assert r.returncode == 0, r.stderr
        assert f"server got: client {i}" in r.stdout
    server.wait_for("handshake OK", n=5)


def test_e2e_application_data_is_encrypted_on_the_wire(server):
    proxy = Proxy(server.port)
    secret = "TOP-SECRET-PLAINTEXT-123"
    r = run_client(proxy.port, server.pk_path, secret)
    assert r.returncode == 0, r.stderr
    wire = b"".join(p for _, _, p in proxy.seen)
    assert secret.encode() not in wire
    assert b"server got" not in wire
    proxy.close()


def test_e2e_bytes_on_the_wire(server):
    proxy = Proxy(server.port)
    r = run_client(proxy.port, server.pk_path)
    assert r.returncode == 0, r.stderr
    sizes = {(d, t): len(p) for d, t, p in proxy.seen}
    # header 3 + (2 + 1568 pk) + (2 + 32 nonce)
    assert sizes[("c2s", CLIENT_HELLO)] == 1607
    # header 3 + (2 + 1568 ct) + (2 + 32) + (2 + 2592 cert) + (2 + 4627 sig)
    assert sizes[("s2c", SERVER_HELLO)] == 8830
    assert sizes[("s2c", FINISHED)] == sizes[("c2s", FINISHED)] == 48
    proxy.close()


# ---- active attacks through the MITM proxy -------------------------------

@pytest.mark.parametrize(
    "direction, msg_type, mutate, reason",
    [
        # Server may reject the key outright (coefficient >= q) or sign the wrong transcript.
        ("c2s", CLIENT_HELLO, lambda p: flip(p, 3 + 2 + 10), "HandshakeError"),
        ("s2c", SERVER_HELLO, lambda p: flip(p, 3 + 2 + 100), "signature"),
        ("s2c", SERVER_HELLO, lambda p: flip(p, len(p) - 1), "signature"),
        ("s2c", FINISHED, lambda p: flip(p, 0), "Finished"),
    ],
    ids=["client-pk", "server-ct", "server-sig", "server-finished"],
)
def test_e2e_tampering_aborts_and_server_survives(server, direction, msg_type, mutate, reason):
    proxy = Proxy(server.port, tamper_once(direction, msg_type, mutate))
    r = run_client(proxy.port, server.pk_path)
    assert_client_failed(r, reason)
    server.wait_for("connection aborted")
    proxy.close()
    # The server keeps serving honest clients afterwards.
    assert run_client(server.port, server.pk_path).returncode == 0


def test_e2e_client_finished_tampered(server):
    proxy = Proxy(server.port, tamper_once("c2s", FINISHED, lambda p: flip(p, 0)))
    run_client(proxy.port, server.pk_path)
    server.wait_for("client Finished MAC is wrong")
    proxy.close()


def test_e2e_downgrade_suite_rejected(server):
    def downgrade(p):
        return p[:1] + struct.pack(">H", 0x0512) + p[3:]

    proxy = Proxy(server.port, tamper_once("c2s", CLIENT_HELLO, downgrade))
    r = run_client(proxy.port, server.pk_path)
    assert r.returncode != 0
    server.wait_for("unsupported version/suite")
    proxy.close()


def test_e2e_impostor_server_rejected(server, tmp_path):
    impostor = ServerProcess(tmp_path, name="impostor")
    try:
        # Client pins the real server's key but is routed to the impostor.
        r = run_client(impostor.port, server.pk_path)
        assert_client_failed(r, "unknown server identity")
    finally:
        impostor.stop()


def test_e2e_tampered_application_record_rejected(server):
    proxy = Proxy(server.port, tamper_once("c2s", APP_DATA, lambda p: flip(p, 0)))
    r = run_client(proxy.port, server.pk_path)
    assert r.returncode != 0
    server.wait_for("record rejected")
    proxy.close()


def test_e2e_replayed_client_flight_rejected(server):
    """Record an honest session, then replay the client's messages on a new connection."""
    proxy = Proxy(server.port)
    assert run_client(proxy.port, server.pk_path, "pay 100 rupees").returncode == 0
    proxy.close()
    recorded = [(t, p) for d, t, p in proxy.seen if d == "c2s"]
    assert [t for t, _ in recorded] == [CLIENT_HELLO, FINISHED, APP_DATA]

    with socket.create_connection(("127.0.0.1", server.port), timeout=WAIT) as s:
        messages.send_frame(s, *recorded[0])             # old ClientHello
        messages.recv_frame(s, SERVER_HELLO)             # fresh ct + nonce_s
        messages.recv_frame(s, FINISHED)
        messages.send_frame(s, *recorded[1])             # old client Finished
        try:
            messages.send_frame(s, *recorded[2])         # old encrypted "pay 100 rupees"
        except OSError:
            pass                                         # server already hung up
    server.wait_for("client Finished MAC is wrong")
    assert server.count("received: pay 100 rupees") == 1  # only the honest one


# ---- robustness against misbehaving clients ------------------------------

@pytest.mark.parametrize(
    "junk",
    [
        b"",                                          # connect and close
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",         # wrong protocol
        struct.pack(">BI", CLIENT_HELLO, 0xFFFFFFFF),  # absurd frame length
        struct.pack(">BI", CLIENT_HELLO, 10) + b"\x01\x10\x24",  # truncated frame
        struct.pack(">BI", CLIENT_HELLO, 3) + b"\x01\x10\x24",   # hello with no fields
    ],
    ids=["empty", "http", "huge-length", "truncated", "no-fields"],
)
def test_e2e_server_survives_garbage(server, junk):
    with socket.create_connection(("127.0.0.1", server.port), timeout=WAIT) as s:
        if junk:
            s.sendall(junk)
    server.wait_for("connection aborted")
    assert run_client(server.port, server.pk_path).returncode == 0


def test_e2e_silent_client_does_not_block_others(server):
    """A client that connects and never speaks must not stall the server forever."""
    silent = socket.create_connection(("127.0.0.1", server.port))
    try:
        r = run_client(server.port, server.pk_path)
        assert r.returncode == 0, r.stderr
    finally:
        silent.close()


def test_e2e_idle_peer_is_dropped(tmp_path):
    s = ServerProcess(tmp_path, timeout=2)
    try:
        with socket.create_connection(("127.0.0.1", s.port), timeout=WAIT) as idle:
            start = time.time()
            assert idle.recv(1) == b""  # server hangs up on us
            assert time.time() - start < 10
        s.wait_for("connection aborted")
    finally:
        s.stop()
