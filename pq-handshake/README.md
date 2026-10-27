# pq-handshake

A simplified TLS 1.3–style handshake that uses **one post-quantum suite**, strong against both classical and quantum attackers:

| Role | Algorithm |
|---|---|
| Key exchange | ML-KEM-1024 (FIPS 203, NIST Category 5) |
| Server authentication | ML-DSA-87 (FIPS 204, NIST Category 5) |
| Key schedule / transcript | HKDF-SHA384 / SHA-384 |
| Records | AES-256-GCM with implicit sequence numbers |

This is the NSA CNSA 2.0 suite. The suite is fixed, with no negotiation, so there is nothing to downgrade to.

> **Caveat:** this is a learning and research implementation. Never use it for real traffic.

## Handshake

```
Client                                        Server
(pk, sk) = ML-KEM-1024.KeyGen()
ClientHello: pk, nonce_c          ------>
                                              (ct, ss) = Encaps(pk)
                                              sig = ML-DSA-87.Sign(transcript)
                                  <------     ServerHello: ct, nonce_s, cert, sig
verify cert pin + sig                         keys = HKDF-SHA384(ss, transcript)
ss = Decaps(sk, ct)               <------     Finished (server MAC)
keys = HKDF-SHA384(ss, transcript)
Finished (client MAC)             ------>     verify client MAC
            <==== AES-256-GCM application data ====>
```

## Modules

| File | Job |
|---|---|
| `kex.py` | ML-KEM-1024 keygen / encaps / decaps, with length checks |
| `auth.py` | ML-DSA-87 keygen / sign / verify |
| `kdf.py` | HKDF-SHA384 extract, expand-label, Finished MACs |
| `transcript.py` | Running SHA-384 over every handshake message |
| `messages.py` | Length-prefixed frames, ClientHello / ServerHello |
| `record.py` | AES-256-GCM record layer and `SecureChannel` |
| `client.py`, `server.py` | Handshake state machines and CLI demo |
| `backend.py` | Chooses liboqs or the pure-Python fallback |

## Setup

Requires Python 3.10 or newer.

```bash
python -m pip install -r requirements.txt
```

That installs the **pure-Python** ML-KEM / ML-DSA (`kyber-py`, `dilithium-py`). They are correct FIPS 203/204 implementations, but they are slow and not constant-time, so they are fine for learning and tests and not for benchmarks.

For real timing numbers, install `liboqs-python` (it needs the native liboqs library, built with CMake). When it imports successfully it is used automatically. To force the pure-Python backend anyway:

```bash
set PQ_BACKEND=pure
```

## Run

```bash
python -m pytest tests
```

Terminal 1:

```bash
python server.py --once
```

Terminal 2:

```bash
python client.py --message "hello"
```

For a presentation, `python demo.py` runs one honest handshake and then four attacks (MITM, tampering, downgrade and replay), pausing between steps. Add `--no-pause` to run it straight through.

The server writes its ML-DSA-87 public key to `server_pk.bin`, and the client pins it. This stands in for certificate-chain validation.

## What the tests check

- ML-KEM-1024 sizes (pk 1568, ct 1568, ss 32) and ML-DSA-87 sizes (pk 2592, sig 4627)
- Both sides derive the same keys and exchange encrypted messages
- A flipped bit in the client's public key, the server's ciphertext or the signature aborts the handshake
- A MITM presenting its own ML-DSA key is rejected
- A downgrade (different suite id, or an ML-KEM-512-sized key) is rejected
- A tampered or replayed AES-GCM record is rejected

`tests/test_e2e.py` runs the real `server.py` and `client.py` as separate processes over TCP, with a man-in-the-middle proxy for the attacks. It checks that:
- many clients can use one server
- application data never appears in plaintext on the wire
- exact message sizes: ClientHello payload is 1,607 B and ServerHello payload is 8,830 B
- tampering with any handshake message or record aborts the handshake
- a recorded client flight replayed on a new connection is rejected
- an impostor server is rejected
- a downgrade is refused
- the server survives garbage input, and idle or silent clients can't block it
