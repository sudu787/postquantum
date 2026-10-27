"""Running SHA-384 hash of every handshake message, in order."""
import hashlib
import struct


class Transcript:
    def __init__(self, _h=None):
        self._h = _h or hashlib.sha384()

    def add(self, msg_type, payload):
        # Hash the type and length too, so message boundaries can't be shifted.
        self._h.update(struct.pack(">BI", msg_type, len(payload)) + payload)

    def fork(self):
        """A copy that can be extended without changing this transcript."""
        return Transcript(self._h.copy())

    def digest(self):
        return self._h.copy().digest()
