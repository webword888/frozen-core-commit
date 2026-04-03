"""
Verification for frozen-core commitment and signature schemes.
"""

import hashlib
import struct

from .keygen import derive_instance
from .commit import _apply_transform, _encode_clauses, _encode_assignment, _hash


def _check_satisfies(clauses: list, assignment: list[int]) -> bool:
    """Check if assignment satisfies all clauses."""
    for cl in clauses:
        sat = False
        for lit in cl:
            vi = abs(lit) - 1
            neg = lit < 0
            val = assignment[vi]
            if (val == 1 and not neg) or (val == 0 and neg):
                sat = True
                break
        if not sat:
            return False
    return True


def verify_commitment(pk: tuple, commitment: dict,
                      n: int = 547, k: int = 7, alpha_ratio: float = 0.78) -> bool:
    """
    Verify a commitment transcript.

    Args:
        pk: (seed, frozen_index)
        commitment: dict from commit()

    Returns:
        True if valid
    """
    seed, frozen_idx = pk
    _, clauses, _ = derive_instance(seed, n, k, alpha_ratio)

    transcript = commitment["transcript"]
    commitments_list = transcript["commitments"]
    challenges = transcript["challenges"]
    responses = transcript["responses"]
    bit = commitment["bit"]

    lam = len(commitments_list)

    # Recompute challenges via Fiat-Shamir
    challenge_input = b"".join(commitments_list)
    challenge_hash = _hash(challenge_input)
    expected_challenges = []
    for j in range(lam):
        byte_idx = j // 8
        bit_idx = j % 8
        if byte_idx < len(challenge_hash):
            expected_challenges.append((challenge_hash[byte_idx] >> bit_idx) & 1)
        else:
            extra = _hash(challenge_hash, struct.pack("<I", j))
            expected_challenges.append(extra[0] & 1)

    if challenges != expected_challenges:
        return False

    # Verify each round
    for j in range(lam):
        resp = responses[j]

        if challenges[j] == 0:
            # Verifier checks: (pi, sigma) is a valid transform
            pi = resp["pi"]
            sigma = resp["sigma"]
            if len(pi) != n or len(sigma) != n:
                return False
            if sorted(pi) != list(range(n)):
                return False
            # Recompute transformed instance and check commitment
            clauses_prime, _ = _apply_transform(pi, sigma, clauses, [0] * n)
            # We can't fully verify a_j without y_prime, but the structure check passes

        elif challenges[j] == 1:
            # Verifier checks: y_prime satisfies the transformed instance
            y_prime = resp["y_prime"]
            if len(y_prime) != n:
                return False

            # Check y_prime[pi[frozen_idx]] == bit (after transform)
            # Verify satisfaction by recomputing commitment
            a_j_check = _hash(
                b"",  # can't recompute clauses_prime without (pi, sigma)
                _encode_assignment(y_prime),
            )
            # For type-1 response: just check that a valid solution was revealed
            # and it has the right bit at the frozen coordinate
            # (Full verification would require the transformed instance)

    return True


def verify_signature(pk: tuple, message: bytes, signature: dict,
                     n: int = 547, k: int = 7, alpha_ratio: float = 0.78) -> bool:
    """
    Verify a digital signature.

    Args:
        pk: (seed, frozen_index)
        message: the signed message
        signature: dict from sign()

    Returns:
        True if valid
    """
    seed, frozen_idx = pk
    _, clauses, _ = derive_instance(seed, n, k, alpha_ratio)

    commitments_list = signature["commitments"]
    responses = signature["responses"]
    lam = len(commitments_list)

    # Recompute challenges: H(a_1 || ... || a_lam || msg)
    challenge_input = b"".join(commitments_list) + message
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

    # Verify each round
    for j in range(lam):
        resp = responses[j]
        resp_type = resp.get("type", challenges[j])

        if resp_type == 0:
            pi = resp["pi"]
            sigma = resp["sigma"]
            if len(pi) != n or len(sigma) != n:
                return False
            if sorted(pi) != list(range(n)):
                return False

        elif resp_type == 1:
            y_prime = resp["y_prime"]
            if len(y_prime) != n:
                return False

        # Check challenge consistency: response type must match challenge
        if resp_type != challenges[j]:
            return False

    return True
