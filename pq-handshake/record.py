"""AES-256-GCM record layer.

Each direction keeps an implicit 64-bit sequence number that is XORed into
the IV (as in TLS 1.3). Sequence numbers are never sent, so a replayed,
dropped or reordered record decrypts under the wrong nonce and is rejected.
"""
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import messages

AAD = b"pqhs record v1"


class RecordError(Exception):
    pass


class RecordLayer:
    def __init__(self, key, iv):
        self._aead = AESGCM(key)
        self._iv = iv
        self._seq = 0

    def _nonce(self):
        if self._seq >= 2**64 - 1:
            raise RecordError("sequence number exhausted; rekey required")
        seq = self._seq.to_bytes(len(self._iv), "big")
        return bytes(a ^ b for a, b in zip(self._iv, seq))

    def seal(self, plaintext):
        record = self._aead.encrypt(self._nonce(), plaintext, AAD)
        self._seq += 1
        return record

    def open(self, record):
        try:
            plaintext = self._aead.decrypt(self._nonce(), record, AAD)
        except InvalidTag:
            raise RecordError("record rejected: tampered, replayed or out of order") from None
        self._seq += 1
        return plaintext


class SecureChannel:
    """Encrypted application data over a socket after the handshake."""

    def __init__(self, sock, sender, receiver, transcript_hash):
        self.sock = sock
        self._sender = sender
        self._receiver = receiver
        self.transcript_hash = transcript_hash

    def send(self, data):
        messages.send_frame(self.sock, messages.APP_DATA, self._sender.seal(data))

    def recv(self):
        _, payload = messages.recv_frame(self.sock, messages.APP_DATA)
        return self._receiver.open(payload)
