# Why one scheme: ML-KEM-1024 instead of the X25519 + ML-KEM-768 hybrid

**Project:** Building a Post-Quantum Handshake · ABV-IIITM Gwalior · October 2026

## The request

The original design combined classical X25519 with post-quantum ML-KEM-768, so an attacker had to break both. The professor asked for **one** scheme that is strong enough on its own to resist **both classical and quantum attacks**.

## 1. Why the single scheme cannot be X25519

X25519 is secure because the elliptic-curve discrete logarithm problem is hard for classical computers. Shor's algorithm solves that problem in polynomial time on a large quantum computer. Larger curves don't help: Shor's cost grows only polynomially with key size, so every elliptic-curve, RSA or finite-field Diffie-Hellman scheme falls, whatever its size. No setting makes a classical scheme quantum-safe.

## 2. Why ML-KEM-1024 resists both kinds of attacker

ML-KEM (FIPS 203, August 2024) is built on the **Module Learning-With-Errors (MLWE)** lattice problem.

- **Classical attackers.** The best known attacks are lattice reduction (BKZ with sieving). For ML-KEM-1024, the core-SVP estimate is about **2^256 operations**. This is NIST **security Category 5**, the highest level, rated at least as hard to break as AES-256 key search.
- **Quantum attackers.** Shor's algorithm needs a hidden periodic structure (a group), which lattice problems don't have. The best known quantum improvements are only small Grover-style speed-ups inside sieving, which leave a quantum core-SVP estimate of about **2^232**. That is still far beyond any foreseeable machine.
- **Active attackers.** ML-KEM applies the Fujisaki–Okamoto transform with *implicit rejection*. This makes it **IND-CCA2 secure**: a tampered ciphertext produces an unrelated random key instead of leaking information.

Going from ML-KEM-768 (Category 3) to **ML-KEM-1024** (Category 5) is how the single scheme is made "so good". It uses the largest standardised parameter set, which leaves the most margin against future improvements in lattice attacks.

## 3. Supporting choices, so nothing classical is left to attack

| Role | Choice | Reason |
|---|---|---|
| Key exchange | ML-KEM-1024 | Category 5, FIPS 203 |
| Server authentication | ML-DSA-87 (FIPS 204) | Ed25519 also falls to Shor, so a quantum attacker could impersonate the server; ML-DSA-87 is Category 5 |
| Key derivation and transcript | HKDF-SHA384 and SHA-384 | Grover only gives a square-root speed-up, so SHA-384 keeps about 192-bit collision security |
| Record encryption | AES-256-GCM | Grover reduces AES-256 to about 128-bit security, which is still out of reach |

## 4. Precedent

This is exactly NSA's **Commercial National Security Algorithm Suite 2.0 (CNSA 2.0)**: ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384. CNSA 2.0 requires pure post-quantum algorithms for U.S. national-security systems, with no hybrid. Our design follows a published government standard rather than an improvised one.

## 5. The honest trade-off and how we handle it

Dropping X25519 removes the hedge against an undiscovered flaw in ML-KEM itself. A hybrid protects you if the new scheme turns out to be broken; a single scheme does not. We reduce that risk in four ways:

1. **Highest parameter set.** Even a substantial improvement in lattice attacks leaves ML-KEM-1024 above the Category 3 level.
2. **Fixed suite, no negotiation.** An attacker can't downgrade the handshake to ML-KEM-512 or to a classical fallback. The transcript hash and Finished MACs detect any attempt.
3. **Standard, tested implementations only.** We use liboqs and Go's `crypto/mlkem`, checked against Known-Answer Tests. We never implement the lattice maths ourselves.
4. **Measured cost.** The benchmark slide compares the classical baseline, the old hybrid and ML-KEM-1024 + ML-DSA-87, so the extra bytes (1,568 B public key and ciphertext, 4,627 B signature) are reported, not hidden.

## References

- NIST FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, August 2024.
- NIST FIPS 204, *Module-Lattice-Based Digital Signature Standard*, August 2024.
- NSA, *Announcing the Commercial National Security Algorithm Suite 2.0*, September 2022 (updated CNSA 2.0 FAQ).
- Bos et al., *CRYSTALS-Kyber Algorithm Specifications*, Round 3, section 5 (security estimates).
- P. W. Shor, *Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer*, SIAM J. Computing, 1997.
