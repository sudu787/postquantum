import os
import socket
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import auth  # noqa: E402
import messages  # noqa: E402
from client import run_client  # noqa: E402
from server import run_server  # noqa: E402

TIMEOUT = 60  # the pure-Python backend is slow


@pytest.fixture(scope="session")
def identity():
    return auth.keygen()


def _relay(src, dst, tamper):
    """Forward frames from src to dst, letting `tamper` rewrite each one."""
    try:
        while True:
            msg_type, payload = messages.recv_frame(src)
            if tamper is not None:
                msg_type, payload = tamper(msg_type, payload)
            messages.send_frame(dst, msg_type, payload)
    except (messages.HandshakeError, OSError):
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def run_pair(identity, tamper=None, client_pin=None, server_identity=None):
    """Run client and server through a man-in-the-middle relay.

    Returns (client_result, server_result); each is a SecureChannel or the
    exception that side raised."""
    c_sock, p1 = socket.socketpair()
    p2, s_sock = socket.socketpair()
    for s in (c_sock, p1, p2, s_sock):
        s.settimeout(TIMEOUT)

    relays = [
        threading.Thread(target=_relay, args=(p1, p2, tamper), daemon=True),
        threading.Thread(target=_relay, args=(p2, p1, tamper), daemon=True),
    ]
    for r in relays:
        r.start()

    result = {}

    def server_side():
        try:
            result["server"] = run_server(s_sock, server_identity or identity)
        except Exception as e:
            result["server"] = e

    st = threading.Thread(target=server_side, daemon=True)
    st.start()
    try:
        result["client"] = run_client(c_sock, client_pin or identity.pk)
    except Exception as e:
        result["client"] = e
    st.join(TIMEOUT)
    return result["client"], result.get("server")


def flip(payload, index):
    b = bytearray(payload)
    b[index] ^= 0x01
    return bytes(b)
