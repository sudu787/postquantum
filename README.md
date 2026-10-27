# Post-Quantum Handshake (ML-KEM-1024)

A simplified TLS 1.3–style handshake built on **one** post-quantum suite: ML-KEM-1024 + ML-DSA-87 + HKDF-SHA384 + AES-256-GCM (NSA CNSA 2.0). It is strong against both classical and quantum attackers. Course project, ABV-IIITM Gwalior.

| Path | What it is |
|---|---|
| [`pq-handshake/`](pq-handshake/) | Python implementation, tests and live demo (see its [README](pq-handshake/README.md)) |
| `Post-Quantum Handshake (ML-KEM-1024).pptx` | Project slides |
| [`justification.md`](justification.md) | Why one post-quantum scheme instead of the X25519 + ML-KEM-768 hybrid |
| [`presentation-guide.md`](presentation-guide.md) | Talk track, demo script and likely questions |
| `run-tests.cmd`, `run-demo.cmd` | Windows launchers for the tests and the demo |

## Quick start

```bash
cd pq-handshake
python -m pip install -r requirements.txt
python -m pytest tests -v
python demo.py
```

> A learning and research implementation: never use it for real traffic.
