import pytest

import auth
import kex
from record import RecordError, RecordLayer


def test_ml_kem_1024_sizes_and_roundtrip():
    pk, sk = kex.keygen()
    ct, ss = kex.encaps(pk)
    assert (len(pk), len(sk), len(ct), len(ss)) == (1568, 3168, 1568, 32)
    assert kex.decaps(sk, ct) == ss


def test_ml_kem_implicit_rejection():
    pk, sk = kex.keygen()
    ct, ss = kex.encaps(pk)
    bad = bytes([ct[0] ^ 1]) + ct[1:]
    assert kex.decaps(sk, bad) != ss  # no exception, just a useless secret


def test_ml_kem_rejects_smaller_parameter_sets():
    with pytest.raises(ValueError):
        kex.encaps(b"\x00" * 800)  # ML-KEM-512 public key size


def test_ml_dsa_87_sizes_and_verify():
    kp = auth.keygen()
    sig = auth.sign(kp.sk, b"transcript")
    assert (len(kp.pk), len(sig)) == (2592, 4627)
    assert auth.verify(kp.pk, b"transcript", sig)
    assert not auth.verify(kp.pk, b"transcripT", sig)
    assert not auth.verify(kp.pk, b"transcript", sig[:-1] + bytes([sig[-1] ^ 1]))


def _pair():
    key, iv = b"k" * 32, b"i" * 12
    return RecordLayer(key, iv), RecordLayer(key, iv)


def test_record_roundtrip():
    tx, rx = _pair()
    for msg in (b"one", b"two", b"three"):
        assert rx.open(tx.seal(msg)) == msg


def test_record_tamper_rejected():
    tx, rx = _pair()
    rec = tx.seal(b"secret")
    with pytest.raises(RecordError):
        rx.open(rec[:-1] + bytes([rec[-1] ^ 1]))


def test_record_replay_rejected():
    tx, rx = _pair()
    rec = tx.seal(b"pay 10 rupees")
    assert rx.open(rec) == b"pay 10 rupees"
    with pytest.raises(RecordError):
        rx.open(rec)
