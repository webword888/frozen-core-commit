"""
Seed-based key generation for frozen-core commitment/signature scheme.

Public key:  (seed, frozen_index) — 34 bytes total
Secret key:  y* (the planted solution)
"""

import hashlib
import struct
import os


def _xof(seed: bytes, context: bytes, length: int) -> bytes:
    """SHAKE256 extensible output."""
    return hashlib.shake_256(seed + context).digest(length)


def derive_solution(seed: bytes, n: int) -> list[int]:
    """Derive planted solution y* from seed."""
    raw = _xof(seed, b"sol", (n + 7) // 8)
    return [(raw[i // 8] >> (i % 8)) & 1 for i in range(n)]


def derive_instance(seed: bytes, n: int, k: int, alpha_ratio: float):
    """
    Derive full planted k-SAT instance from 32-byte seed.

    Returns (y_star, clauses, m) where each clause is a list of
    signed literals in DIMACS convention (1-indexed, negative = negated).
    """
    y_star = derive_solution(seed, n)

    alpha_s = (2 ** k) * 0.693147  # 2^k ln 2
    alpha = alpha_ratio * alpha_s
    m = int(alpha * n)

    # Derive all randomness from seed
    need = m * (k * 4 + k * 2) * 2
    clause_rand = _xof(seed, b"cls", need)

    clauses = []
    offset = 0

    for _ in range(m):
        # Select k distinct variables via Fisher-Yates
        selected = []
        candidates = list(range(n))
        for j in range(k):
            val = struct.unpack_from("<I", clause_rand, offset)[0]
            offset += 4
            idx = val % (n - j)
            selected.append(candidates[idx])
            candidates[idx] = candidates[n - j - 1]

        # Sample signs conditioned on y* satisfying the clause
        while True:
            signs = [(clause_rand[offset + j]) & 1 for j in range(k)]
            offset += k
            if any((y_star[selected[j]] ^ signs[j]) == 1 for j in range(k)):
                break

        # Convert to DIMACS literals (1-indexed)
        clause = []
        for j in range(k):
            v = selected[j] + 1
            clause.append(v if signs[j] == 0 else -v)
        clauses.append(clause)

    return y_star, clauses, m


def find_frozen_coordinate(y_star: list[int], clauses: list, n: int) -> int:
    """Find first variable with >= 1 support clause (unique satisfying literal)."""
    support = [0] * n
    for cl in clauses:
        sat_indices = []
        for lit in cl:
            vi = abs(lit) - 1
            neg = lit < 0
            if (y_star[vi] == 1 and not neg) or (y_star[vi] == 0 and neg):
                sat_indices.append(vi)
        if len(sat_indices) == 1:
            support[sat_indices[0]] += 1

    for i in range(n):
        if support[i] >= 1:
            return i
    raise RuntimeError("No frozen coordinate found (should not happen at our densities)")


def keygen(n: int = 547, k: int = 7, alpha_ratio: float = 0.78, seed: bytes | None = None):
    """
    Generate a key pair.

    Returns:
        pk: (seed, frozen_index)  — 34 bytes public key
        sk: y_star               — planted solution (secret)
    """
    if seed is None:
        seed = os.urandom(32)
    assert len(seed) == 32

    y_star, clauses, m = derive_instance(seed, n, k, alpha_ratio)
    frozen_idx = find_frozen_coordinate(y_star, clauses, n)

    pk = (seed, frozen_idx)
    sk = y_star
    return pk, sk
