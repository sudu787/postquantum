import struct

import pytest

import auth
import messages
from conftest import flip, run_pair
from messages import CLIENT_HELLO, SERVER_HELLO, HandshakeError
from record import RecordError, SecureChannel

# Byte offsets inside the hello payloads (see messages.py):
# header = version (1) + suite (2), then each field = length (2) + bytes.
CH_PK_BYTE = 3 + 2 + 10
SH_CT_BYTE = 3 + 2 + 100


def _tamper(target_type, index):
    def tamper(msg_type, payload):
        if msg_type == target_type:
            payload = flip(payload, index)
        return msg_type, payload
    return tamper


def test_both_sides_derive_identical_keys_and_talk(identity):
    client, server = run_pair(identity)
    assert isinstance(client, SecureChannel), client
    assert isinstance(server, SecureChannel), server
    assert client.transcript_hash == server.transcript_hash

    client.send(b"ping from client")
    assert server.recv() == b"ping from client"
    server.send(b"pong from server")
    assert client.recv() == b"pong from server"


@pytest.mark.parametrize(
    "target, index",
    [
        (CLIENT_HELLO, CH_PK_BYTE),   # flipped bit in the ML-KEM public key
        (SERVER_HELLO, SH_CT_BYTE),   # flipped bit in the ML-KEM ciphertext
        (SERVER_HELLO, -1),           # flipped bit in the ML-DSA signature
    ],
    ids=["client-pk", "server-ct", "server-sig"],
)
def test_tampered_handshake_aborts(identity, target, index):
    client, server = run_pair(identity, tamper=_tamper(target, index))
    assert isinstance(client, HandshakeError)
    assert isinstance(server, HandshakeError)


def test_mitm_with_its_own_key_is_rejected(identity):
    attacker = auth.keygen()
    client, _ = run_pair(identity, server_identity=attacker)
    assert isinstance(client, HandshakeError)
    assert "identity" in str(client)


def test_downgrade_to_weaker_suite_is_rejected(identity):
    def downgrade(msg_type, payload):
        if msg_type == CLIENT_HELLO:
            # Claim a different suite id (as if offering ML-KEM-512).
            payload = payload[:1] + struct.pack(">H", 0x0512) + payload[3:]
        return msg_type, payload

    client, server = run_pair(identity, tamper=downgrade)
    assert isinstance(server, HandshakeError)
    assert "suite" in str(server)
    assert isinstance(client, HandshakeError)


def test_short_ml_kem_key_is_rejected():
    hello = messages.ClientHello(pk=b"\x00" * 800, nonce=b"\x00" * 32).encode()
    with pytest.raises(HandshakeError):
        messages.ClientHello.decode(hello)


def test_tampered_application_record_is_rejected(identity):
    client, server = run_pair(identity)
    sealed = client._sender.seal(b"transfer 100")
    with pytest.raises(RecordError):
        server._receiver.open(flip(sealed, 0))
