# frozen-core-commit

**Post-quantum commitment and signature schemes from planted k-SAT frozen-core isolation.**

A fourth post-quantum hardness family: frozen-core constraint satisfaction. 34-byte public keys. Proved barriers against 5 quantum attack families. Commitment + digital signature schemes with formal security proofs.

## What's New

- **New hardness family.** Security reduces to the hardness of planted k-SAT — structurally different from lattices, hashes, and codes.
- **34-byte public keys** at all NIST security levels via seed-based instance compression (smaller than CRYSTALS-Kyber's 1,568 bytes).
- **Proved quantum barriers** against quantum walks, QAOA (all depths), quantum annealing, Montanaro DPLL, and low-degree polynomials. Only Grover remains, mitigated by standard parameter doubling.
- **Concrete classical security.** CDCL solver benchmarks yield attack cost 2^{0.234n}, with R² = 0.985.
- **Commitment + signature.** Sigma protocol commitment with Fiat-Shamir signature scheme. Completeness, soundness, zero-knowledge, and EUF-CMA unforgeability proved.

## Install

```bash
pip install .
```

For benchmarks (requires SAT solvers):
```bash
pip install ".[bench]"
```

## Quick Start

```python
from fci_commit import keygen, commit, verify_commitment, sign, verify_signature

# Generate keys (34-byte public key)
pk, sk = keygen(n=547)  # NIST Level 1

# Commit to a bit
bit = sk[pk[1]]  # value at frozen coordinate
c = commit(pk, sk, bit, lam=128, n=547)
assert verify_commitment(pk, c, n=547)

# Sign a message
sig = sign(pk, sk, b"Hello, post-quantum world!", lam=128, n=547)
assert verify_signature(pk, b"Hello, post-quantum world!", sig, n=547)
```

## Parameters

| Level | λ | n | Clauses | PK Size | Proof/Sig Size | Classical Security |
|-------|-----|-------|---------|---------|----------------|-------------------|
| NIST-1 | 128 | 547 | 37,854 | 34 B | 12.5 KB | 2^128 |
| NIST-3 | 192 | 820 | 56,747 | 34 B | 25.1 KB | 2^192 |
| NIST-5 | 256 | 1,094 | 75,708 | 34 B | 42.0 KB | 2^256 |

## Benchmarks

```bash
# Seed compression (shows 34-byte PK at all levels)
python benchmarks/bench_seed_compression.py

# Classical cryptanalysis (Glucose/MiniSat scaling)
python benchmarks/bench_cryptanalysis.py

# Cluster separation distance (Δ_min/n ≥ 0.34)
python benchmarks/bench_separation.py
```

## Paper

**"Frozen Core Isolation and Quantum-Resistant Cryptographic Commitments from Planted k-SAT"**
John Rhodes, 2026.

- PDF: [paper/frozen-core-paper-v5f.pdf](paper/frozen-core-paper-v5f.pdf)
- Zenodo: [10.5281/zenodo.19403853](https://zenodo.org/records/19403853)
- ePrint: *(awaiting review — submitted to IACR Cryptology ePrint Archive)*

## How It Works

1. **KeyGen**: Sample a 32-byte seed. Derive a planted k-SAT instance via SHAKE256. Identify a frozen coordinate (a variable that is the unique satisfying literal in at least one clause). Public key = (seed, frozen_index).

2. **Commit(b)**: Prove in zero-knowledge that you know a satisfying assignment with y[frozen_index] = b, using a sigma protocol repeated λ times with Fiat-Shamir.

3. **Binding**: To break binding, an adversary must find a satisfying assignment in a *different cluster* — at Hamming distance ≥ 0.34n from the planted solution. This requires solving planted k-SAT, which costs 2^{0.234n} operations.

4. **Sign**: Same sigma protocol, but challenges are derived from H(commitments || message).

## Status

This is a **reference implementation** for the accompanying paper. It is not optimized for production use. The primary contribution is the identification and analysis of a new post-quantum hardness family, not a drop-in replacement for existing schemes.

## License

MIT

## Author

John Rhodes
