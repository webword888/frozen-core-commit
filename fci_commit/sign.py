"""
Digital signature scheme from planted k-SAT frozen-core isolation.

Sign:    Fiat-Shamir transform of the sigma protocol, binding the message
         into the challenge derivation.
Verify:  Recompute challenges from commitments + message, check responses.
"""

import hashlib
import os
import struct

from .keygen import derive_instance
from .commit import _apply_transform, _random_permutation, _encode_clauses, _encode_assignment, _hash


def sign(pk: tuple, sk: list[int], message: bytes, lam: int = 128,
         n: int = 547, k: int = 7, alpha_ratio: float = 0.78) -> dict:
    """
    Sign a message.

    Args:
        pk: (seed, frozen_index)
        sk: y_star (planted solution)
        message: bytes to sign
        lam: security parameter

    Returns:
        signature dict
    """
    seed, frozen_idx = pk
    y_star = sk
    _, clauses, _ = derive_instance(seed, n, k, alpha_ratio)

    rounds = []
    commitments = []

    for j in range(lam):
        rand_pi = os.urandom(n * 4)
        pi = _random_permutation(n, rand_pi)
        sigma = [b & 1 for b in os.urandom(n)]

        clauses_prime, y_prime = _apply_transform(pi, sigma, clauses, y_star)

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
        })

    # Fiat-Shamir: challenges derived from commitments AND message
    challenge_input = b"".join(commitments) + message
    challenge_hash = _hash(challenge_input)
    challenges = []
    for j in range(lam):
        byte_idx = j // 8
        bit_idx = j % 8
        if byte_idx < len(challenge_hash):
            challenges.append((challenge_hash[byte_idx] >> bit_idx) & 1)
        else:
            extra = _hash(challenge_hash, struct.pack("<I", j))
            challenges.append(extra[0] & 1)

    # Build responses
    responses = []
    for j in range(lam):
        if challenges[j] == 0:
            responses.append({"type": 0, "pi": rounds[j]["pi"], "sigma": rounds[j]["sigma"]})
        else:
            responses.append({"type": 1, "y_prime": rounds[j]["y_prime"]})

    return {
        "commitments": commitments,
        "challenges": challenges,
        "responses": responses,
    }
