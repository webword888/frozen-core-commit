"""
fci_commit: Post-quantum commitment and signature schemes
from planted k-SAT frozen-core isolation.

34-byte public keys. Proved barriers against 5 quantum attack families.
"""

__version__ = "0.1.0"

from .keygen import keygen, derive_instance, find_frozen_coordinate
from .commit import commit, open_commitment
from .sign import sign
from .verify import verify_commitment, verify_signature
