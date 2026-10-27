"""Wire format: length-prefixed frames and the two hello messages.

Frame:   type (1 byte) | length (4 bytes) | payload
Fields:  length (2 bytes) | bytes, repeated

The suite is fixed (no negotiation), so there is nothing to downgrade to:
any other version, suite or key size is rejected.
"""
import struct
from dataclasses import dataclass

import auth
import kex

VERSION = 1
SUITE_ID = 0x1024  # ML-KEM-1024 + ML-DSA-87 + HKDF-SHA384 + AES-256-GCM
NONCE_LEN = 32
MAX_FRAME = 1 << 16
SIG_CONTEXT = b"pqhs server signature v1"

CLIENT_HELLO = 1
SERVER_HELLO = 2
FINISHED = 3
APP_DATA = 4


class HandshakeError(Exception):
    pass


# ---- framing ---------------------------------------------------------------

def send_frame(sock, msg_type, payload):
    sock.sendall(struct.pack(">BI", msg_type, len(payload)) + payload)


def _recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise HandshakeError("connection closed by peer")
        buf += chunk
    return bytes(buf)


def recv_frame(sock, expected=None):
    msg_type, length = struct.unpack(">BI", _recv_exact(sock, 5))
    if length > MAX_FRAME:
        raise HandshakeError(f"frame too large: {length} bytes")
    payload = _recv_exact(sock, length)
    if expected is not None and msg_type != expected:
        raise HandshakeError(f"unexpected message type {msg_type}, wanted {expected}")
    return msg_type, payload


# ---- fields ----------------------------------------------------------------

def _pack(*fields):
    return b"".join(struct.pack(">H", len(f)) + f for f in fields)


def _unpack(data, count):
    fields, pos = [], 0
    for _ in range(count):
        if pos + 2 > len(data):
            raise HandshakeError("truncated message")
        (n,) = struct.unpack_from(">H", data, pos)
        pos += 2
        if pos + n > len(data):
            raise HandshakeError("truncated field")
        fields.append(data[pos:pos + n])
        pos += n
    if pos != len(data):
        raise HandshakeError("trailing bytes in message")
    return fields


def _header():
    return struct.pack(">BH", VERSION, SUITE_ID)


def _check_header(data):
    if len(data) < 3:
        raise HandshakeError("truncated header")
    version, suite = struct.unpack_from(">BH", data, 0)
    if version != VERSION or suite != SUITE_ID:
        raise HandshakeError(f"unsupported version/suite {version}/{suite:#06x}")
    return data[3:]


def _check_len(name, value, length):
    if len(value) != length:
        raise HandshakeError(f"{name} must be {length} bytes, got {len(value)}")


# ---- messages --------------------------------------------------------------

@dataclass
class ClientHello:
    pk: bytes
    nonce: bytes

    def encode(self):
        return _header() + _pack(self.pk, self.nonce)

    @classmethod
    def decode(cls, data):
        pk, nonce = _unpack(_check_header(data), 2)
        _check_len("ML-KEM-1024 public key", pk, kex.PK_LEN)
        _check_len("client nonce", nonce, NONCE_LEN)
        return cls(pk, nonce)


@dataclass
class ServerHello:
    ct: bytes
    nonce: bytes
    cert: bytes  # the server's ML-DSA-87 public key; stands in for a certificate chain
    sig: bytes = b""

    def core(self):
        """Everything except the signature: this is what the signature covers."""
        return _header() + _pack(self.ct, self.nonce, self.cert)

    def encode(self):
        return self.core() + _pack(self.sig)

    @classmethod
    def decode(cls, data):
        ct, nonce, cert, sig = _unpack(_check_header(data), 4)
        _check_len("ML-KEM-1024 ciphertext", ct, kex.CT_LEN)
        _check_len("server nonce", nonce, NONCE_LEN)
        _check_len("ML-DSA-87 public key", cert, auth.PK_LEN)
        _check_len("ML-DSA-87 signature", sig, auth.SIG_LEN)
        return cls(ct, nonce, cert, sig)
