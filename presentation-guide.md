# Presenting to the professor

**Goal of the meeting:** show that you followed the advice ("one scheme strong against both classical and quantum attacks"), that the choice is justified, and that it works.

**Length:** about 15 minutes: 10 of talking and demo, plus questions.

## Before the meeting (do this the day before)

1. **Open the deck in PowerPoint and look at every slide.** It was edited without being viewed. Check slide 3 (design), slide 9 (attack table, which gained a row) and slide 10 (size table, which gained a column) for text that overflows.
2. **Print or email `justification.md`** as a one-page handout.
3. **Do a dry run of the demo** in a terminal with a large font (Ctrl + scroll wheel):
   ```
   cd Documents\PQ-Handshake\pq-handshake
   ~\.venvs\pq-handshake\Scripts\python.exe -m pytest tests -q
   ~\.venvs\pq-handshake\Scripts\python.exe demo.py
   ```
   The tests should end with `35 passed`. The demo pauses after each step; press Enter to continue.
4. **Backup plan:** if the laptop or demo fails on the day, take a screenshot of a good demo run and of the `35 passed` output, and keep both ready.

## Running order

| Time | What | Key line to say |
|---|---|---|
| 0:00 | **Slide 1** Title | "You asked for one scheme strong against both kinds of attacker. This is that design." |
| 0:30 | **Slide 2** Problem | "Shor breaks elliptic curves *at any key size*. So X25519 can't be made strong enough; making it bigger doesn't help." |
| 1:30 | **Slide 3** Design ★ | "So the one scheme has to be post-quantum. We took ML-KEM to its highest level, 1024, which is NIST Category 5. Every other part is post-quantum or 256-bit symmetric. This is exactly NSA's CNSA 2.0 suite." Then name the trade-off yourself, before they ask. |
| 3:00 | **Slide 4** Handshake | Walk the arrows: one round trip, the client sends pk, the server sends ct + signature, both derive keys, Finished MACs. |
| 4:00 | **Slide 5** Key schedule | "There's one secret, so there's no combiner, but it still only goes through HKDF, and everything is bound to the transcript." |
| 5:00 | **LIVE DEMO** ★ | Run `demo.py` (script below). |
| 9:00 | **Slides 6–7** Stack, code | "Libraries for the math, our code for the protocol. 35 automated tests, including end-to-end tests with real processes." |
| 10:00 | **Slides 8–10** Plan, attacks, benchmarks | "Weeks 1–3 are done. Week 4 is benchmarks; the cost is bytes: about 10 KB per handshake instead of a few hundred bytes." |
| 11:00 | **Slide 11** Outputs | Close with the caveat: research code, not for real traffic. |

★ = the two moments that matter most. If time is short, cut slides 6–8, not these.

## Demo script: what to say at each pause

1. **Setup:** "Everything is ML-KEM-1024, ML-DSA-87, SHA-384 and AES-256. The client pins the server's 2.6 KB public key."
2. **Honest handshake:** point at the sizes (1,607 B and 8,830 B: "that's the price of quantum safety"), then at the ciphertext line: "the eavesdropper sees only random bytes."
3. **Man-in-the-middle:** "The attacker uses its own key. The client refuses because the key isn't the pinned one."
4. **Tampering:** "One flipped bit in the ciphertext and the ML-DSA signature fails."
5. **Downgrade:** "The attacker asks for ML-KEM-512. There is no negotiation, so the server simply refuses."
6. **Replay:** "A recorded payment is replayed. The server picks a fresh nonce and ciphertext each time, so the old Finished MAC is useless."

## Questions to expect, with short answers

**"Why not just use a bigger elliptic curve or RSA key?"**
Shor's algorithm runs in polynomial time in the key size, so a quantum computer breaks every size. No classical parameter is quantum-safe.

**"Chrome and Cloudflare use a hybrid. Why are you dropping it?"**
Because you asked for a single scheme. The hybrid's only extra protection is against a flaw in ML-KEM itself. We cover that risk with the largest parameter set, a standard tested library and no negotiation. NSA's CNSA 2.0 makes the same call and requires pure ML-KEM-1024.

**"What if ML-KEM is broken tomorrow?"**
That is the honest trade-off, and it is on slide 3. The fallback would be a code-based KEM such as Classic McEliece or HQC. Our `kex.py` interface is three functions, so swapping the scheme is a small change.

**"Why 1024 and not 768?"**
768 is Category 3 (about AES-192). 1024 is Category 5 (about AES-256). The best known attacks cost about 2^256 classically and about 2^232 quantumly, which leaves the most margin if lattice attacks improve. It costs only 384 extra bytes for the key and 480 for the ciphertext.

**"Why ML-DSA-87 and not Falcon or SLH-DSA?"**
ML-DSA is a final standard (FIPS 204) and is simple to implement safely. Falcon (FN-DSA) is smaller but not finalised yet and is tricky to implement. SLH-DSA is very conservative but its signatures are tens of kilobytes.

**"Doesn't Grover's algorithm break AES?"**
Grover only halves the effective key length. AES-256 becomes about 128-bit, and SHA-384 keeps about 192-bit collision resistance. Both are still out of reach.

**"Did you implement the cryptography yourselves?"**
No, only the protocol. The math comes from liboqs or the pure-Python FIPS 203/204 implementations. Rolling your own lattice code is a classic mistake.

**"Is the pure-Python version secure?"**
It is correct but not constant-time and is slow, so it is only for learning and tests. Benchmarks and anything serious use liboqs or Go's `crypto/mlkem`.

**"How do you know it works?"**
There are 35 automated tests. They cover correct sizes, both sides deriving the same keys, every tampered message being rejected, MITM, downgrade and replay being blocked, plaintext never appearing on the wire, and the server surviving garbage input. End-to-end testing also found two real server bugs (a denial-of-service and a socket leak), which we fixed.

**"What does ML-KEM do if the ciphertext is modified?"**
Implicit rejection. Decapsulation returns an unrelated random secret instead of an error, so the attacker learns nothing and the Finished MAC check fails.

**"What's next?"**
Week 4 benchmarks on Linux (WSL2) with liboqs and `tc netem` for latency and packet loss, then the harvest-now-decrypt-later demo.
