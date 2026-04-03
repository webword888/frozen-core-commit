"""
Commitment scheme from planted k-SAT frozen-core isolation.

Commit(b):  Produce a NIZK proof that "I know y satisfying Phi with y_i = b"
Open(b):    Reveal b and the proof transcript
Verify:     Check the proof transcript
"""

import hashlib
import os
import struct

from .keygen import derive_instance


def _hash(*parts: bytes) -> bytes:
    """SHA-256 hash of concatenated parts."""
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _apply_transform(pi: list[int], sigma: list[int], clauses: list, y_star: list[int]):
    """
    Apply (pi, sigma) to instance and solution.
    pi:    permutation on [n]
    sigma: sign flip vector in {0,1}^n (1 = flip)
    """
    n = len(y_star)
    # Permute and flip solution
    y_prime = [(y_star[pi[i]] ^ sigma[i]) for i in range(n)]

    # Transform clauses
    clauses_prime = []
    for cl in clauses:
        new_cl = []
        for lit in cl:
            vi = abs(lit) - 1  # 0-indexed
            neg = 1 if lit < 0 else 0
            new_vi = pi[vi]
            new_neg = neg ^ sigma[new_vi]
            new_lit = (new_vi + 1) if new_neg == 0 else -(new_vi + 1)
            new_cl.append(new_lit)
        clauses_prime.append(new_cl)

    return clauses_prime, y_prime


def _random_permutation(n: int, rand_bytes: bytes) -> list[int]:
    """Fisher-Yates shuffle from random bytes."""
    perm = list(range(n))
    offset = 0
    for i in range(n - 1, 0, -1):
        val = struct.unpack_from("<I", rand_bytes, offset)[0]
        offset += 4
        j = val % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def _encode_clauses(clauses: list) -> bytes:
    """Deterministic encoding of clause list for hashing."""
    parts = []
    for cl in clauses:
        parts.append(struct.pack(f"<{len(cl)}i", *cl))
    return b"".join(parts)


def _encode_assignment(y: list[int]) -> bytes:
    """Pack assignment as bytes."""
    n = len(y)
    out = bytearray((n + 7) // 8)
    for i in range(n):
        if y[i]:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def commit(pk: tuple, sk: list[int], bit: int, lam: int = 128,
           n: int = 547, k: int = 7, alpha_ratio: float = 0.78) -> dict:
    """
    Commit to bit b in {0, 1}.

    Args:
        pk: (seed, frozen_index)
        sk: y_star (planted solution)
        bit: 0 or 1
        lam: security parameter (number of rounds)

    Returns:
        commitment dict with 'bit', 'transcript', 'commitment_hash'
    """
    assert bit in (0, 1)
    seed, frozen_idx = pk
    assert sk[frozen_idx] == bit, "Cannot commit to bit != y*[frozen_idx]"

    y_star = sk
    _, clauses, _ = derive_instance(seed, n, k, alpha_ratio)

    rounds = []
    commitments = []

    for j in range(lam):
        # Generate random (pi, sigma)
        rand_pi = os.urandom(len(y_star) * 4)
        pi = _random_permutation(len(y_star), rand_pi)
        sigma = [b & 1 for b in os.urandom(len(y_star))]
        rand_seed = os.urandom(32)  # seed to reconstruct (pi, sigma)

        clauses_prime, y_prime = _apply_transform(pi, sigma, clauses, y_star)

        # Commitment for this round
        a_j = _hash(
            _encode_clauses(clauses_prime),
            _encode_assignment(y_prime),
        )
        commitments.append(a_j)

        rounds.append({
            "pi": pi,
            "sigma": sigma,
            "clauses_prime": clauses_prime,
            "y_prime": y_prime,
            "a_j": a_j,
            "rand_seed": rand_seed,
        })

    # Derive challenges via Fiat-Shamir
    challenge_input = b"".join(commitments)
    challenge_hash = _hash(challenge_input)
    challenges = []
    for j in range(lam):
        byte_idx = j // 8
        bit_idx = j % 8
        if byte_idx < len(challenge_hash):
            challenges.append((challenge_hash[byte_idx] >> bit_idx) & 1)
        else:
            # Need more challenge bits
            extra = _hash(challenge_hash, struct.pack("<I", j))
            challenges.append(extra[0] & 1)

    # Build responses
    responses = []
    for j in range(lam):
        if challenges[j] == 0:
            responses.append({"type": 0, "pi": rounds[j]["pi"], "sigma": rounds[j]["sigma"]})
        else:
            responses.append({"type": 1, "y_prime": rounds[j]["y_prime"]})

    transcript = {
        "commitments": commitments,
        "challenges": challenges,
        "responses": responses,
    }

    commitment_hash = _hash(b"commit", challenge_input)

    return {
        "bit": bit,
        "transcript": transcript,
        "commitment_hash": commitment_hash,
    }


def open_commitment(commitment: dict) -> tuple:
    """
    Open a commitment: reveal bit and transcript.

    Returns (bit, transcript)
    """
    return commitment["bit"], commitment["transcript"]
