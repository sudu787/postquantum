"""ML-KEM-1024 key encapsulation (FIPS 203, NIST security Category 5).

keygen() -> (pk, sk)
encaps(pk) -> (ct, ss)
decaps(sk, ct) -> ss

Lengths are checked up front, so a smaller parameter set (for example an
800-byte ML-KEM-512 key) is rejected instead of silently accepted.
"""
from backend import load_oqs

ALG = "ML-KEM-1024"
PK_LEN = 1568
SK_LEN = 3168
CT_LEN = 1568
SS_LEN = 32

_oqs = load_oqs()

if _oqs is not None:
    BACKEND = "liboqs"

    def _keygen():
        with _oqs.KeyEncapsulation(ALG) as kem:
            pk = kem.generate_keypair()
            return pk, kem.export_secret_key()

    def _encaps(pk):
        with _oqs.KeyEncapsulation(ALG) as kem:
            ct, ss = kem.encap_secret(pk)
            return ct, ss

    def _decaps(sk, ct):
        with _oqs.KeyEncapsulation(ALG, secret_key=sk) as kem:
            return kem.decap_secret(ct)

else:
    from kyber_py.ml_kem import ML_KEM_1024

    BACKEND = "kyber-py (pure Python, prototype only)"

    def _keygen():
        ek, dk = ML_KEM_1024.keygen()
        return ek, dk

    def _encaps(pk):
        ss, ct = ML_KEM_1024.encaps(pk)
        return ct, ss

    def _decaps(sk, ct):
        return ML_KEM_1024.decaps(sk, ct)


def _check(name, value, length):
    if len(value) != length:
        raise ValueError(f"{ALG}: {name} must be {length} bytes, got {len(value)}")


def keygen():
    pk, sk = _keygen()
    return bytes(pk), bytes(sk)


def encaps(pk):
    _check("public key", pk, PK_LEN)
    ct, ss = _encaps(pk)
    return bytes(ct), bytes(ss)


def decaps(sk, ct):
    """Decapsulate. A tampered ct does not raise: ML-KEM's implicit rejection
    returns an unrelated random-looking secret, so the Finished MAC check fails."""
    _check("secret key", sk, SK_LEN)
    _check("ciphertext", ct, CT_LEN)
    return bytes(_decaps(sk, ct))
