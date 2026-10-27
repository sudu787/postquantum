"""ML-DSA-87 signatures (FIPS 204, NIST security Category 5).

The server signs the handshake transcript so a man-in-the-middle cannot
substitute its own ML-KEM ciphertext. No classical signature is used.
"""
from dataclasses import dataclass

from backend import load_oqs

ALG = "ML-DSA-87"
PK_LEN = 2592
SK_LEN = 4896
SIG_LEN = 4627


@dataclass(frozen=True)
class KeyPair:
    pk: bytes
    sk: bytes


_oqs = load_oqs()

if _oqs is not None:
    BACKEND = "liboqs"

    def _keygen():
        with _oqs.Signature(ALG) as s:
            pk = s.generate_keypair()
            return pk, s.export_secret_key()

    def _sign(sk, msg):
        with _oqs.Signature(ALG, secret_key=sk) as s:
            return s.sign(msg)

    def _verify(pk, msg, sig):
        with _oqs.Signature(ALG) as s:
            return s.verify(msg, sig, pk)

else:
    from dilithium_py.ml_dsa import ML_DSA_87

    BACKEND = "dilithium-py (pure Python, prototype only)"

    def _keygen():
        pk, sk = ML_DSA_87.keygen()
        return pk, sk

    def _sign(sk, msg):
        return ML_DSA_87.sign(sk, msg)

    def _verify(pk, msg, sig):
        return ML_DSA_87.verify(pk, msg, sig)


def keygen():
    pk, sk = _keygen()
    return KeyPair(pk=bytes(pk), sk=bytes(sk))


def sign(sk, msg):
    return bytes(_sign(sk, msg))


def verify(pk, msg, sig):
    """Return True only for a valid signature; never raises on bad input."""
    if len(pk) != PK_LEN or len(sig) != SIG_LEN:
        return False
    try:
        return bool(_verify(pk, msg, sig))
    except Exception:
        return False
