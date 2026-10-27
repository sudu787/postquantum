"""HKDF-SHA384 key schedule.

There is one shared secret (from ML-KEM-1024), so there is no combiner. The
secret is never used as a key directly: it goes through HKDF-Extract, and
every derived key is bound to the transcript hash via HKDF-Expand.
"""
import hashlib
import hmac
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

HASH_LEN = 48  # SHA-384
KEY_LEN = 32   # AES-256
IV_LEN = 12    # AES-GCM nonce
LABEL_PREFIX = b"pqhs "


@dataclass(frozen=True)
class HandshakeKeys:
    client_key: bytes
    client_iv: bytes
    client_finished: bytes
    server_key: bytes
    server_iv: bytes
    server_finished: bytes


def hkdf_extract(salt, ikm):
    return hmac.new(salt or b"\x00" * HASH_LEN, ikm, hashlib.sha384).digest()


def expand_label(secret, label, context, length):
    """TLS 1.3-style HKDF-Expand-Label with a project-specific prefix."""
    full_label = LABEL_PREFIX + label
    info = struct.pack(">H", length) + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context
    return HKDFExpand(algorithm=hashes.SHA384(), length=length, info=info).derive(secret)


def derive(shared_secret, transcript_hash):
    """Derive both directions' traffic keys and Finished keys."""
    hs = hkdf_extract(None, shared_secret)
    c_secret = expand_label(hs, b"c traffic", transcript_hash, HASH_LEN)
    s_secret = expand_label(hs, b"s traffic", transcript_hash, HASH_LEN)
    return HandshakeKeys(
        client_key=expand_label(c_secret, b"key", b"", KEY_LEN),
        client_iv=expand_label(c_secret, b"iv", b"", IV_LEN),
        client_finished=expand_label(c_secret, b"finished", b"", HASH_LEN),
        server_key=expand_label(s_secret, b"key", b"", KEY_LEN),
        server_iv=expand_label(s_secret, b"iv", b"", IV_LEN),
        server_finished=expand_label(s_secret, b"finished", b"", HASH_LEN),
    )


def finished_mac(finished_key, transcript_hash):
    return hmac.new(finished_key, transcript_hash, hashlib.sha384).digest()
