"""A Merkle tree over log entries, per RFC 6962 / RFC 9162, with inclusion and consistency proofs.

SPDX-License-Identifier: MIT — Copyright (c) 2026 CAID LLC (Underwrit). MIT, unlike the rest of the
package (proprietary, see LICENSE): this is embedded in every bundle's `verify.py`, which must be copyable anywhere.
See NOTICE.


What this buys over the linear chain in `chain.py`, said precisely (Crosby & Wallach, USENIX '09):
with a hash chain, proving one entry belongs to a commitment needs every intermediate entry, and a
logger that knows a commitment will never be audited can rewrite what it fixes. With a tree, a
bundle carrying a *subset* of entries can prove each one's position against a signed root in
O(log n) hashes — so a missing index inside a requested range is visible — and a consistency proof
between two roots shows the log only grew between them.

Neither structure stops a log from showing different views to different people. That needs the
root published somewhere the logger cannot rewrite: a witness. The control plane is the natural
witness for a data plane (it sees size and root, never an argument), and that protocol is the next
step; this module is the arithmetic both sides share.

Domain separation is required: leaves hash as `SHA-256(0x00 ‖ data)` and interior nodes as
`SHA-256(0x01 ‖ left ‖ right)`, or a leaf could be forged as a node ("second preimage").
Verified against the RFC 9162 §2.1.5 test vectors in `tests/test_evidence_v2.py`.
"""

from __future__ import annotations

import hashlib

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    """k such that k < n <= 2k, for n >= 2 — the split RFC 6962 uses."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root(leaves: list[bytes]) -> bytes:
    """Merkle Tree Hash of already-hashed leaves (each from `leaf_hash`)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    return node_hash(root(leaves[:k]), root(leaves[k:]))


def inclusion_proof(index: int, leaves: list[bytes]) -> list[bytes]:
    """Audit path for leaf `index` in a tree of these leaves (RFC 9162 §2.1.3.1)."""
    n = len(leaves)
    if not 0 <= index < n:
        raise IndexError(f"leaf {index} not in a tree of {n}")
    if n == 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [root(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [root(leaves[:k])]


def root_from_inclusion(index: int, size: int, leaf: bytes, proof: list[bytes]) -> bytes:
    """Recompute the root a proof implies (RFC 9162 §2.1.3.2). Compare it to the signed root.

    Every proof node is consumed and the path length is checked against the tree shape — immudb's
    CVE-2022-36111 was a verifier that trusted a shortcut.
    """
    if not 0 <= index < size:
        raise ValueError("leaf index outside the tree")
    fn, sn = index, size - 1
    r = leaf
    for p in proof:
        if sn == 0:
            raise ValueError("proof longer than the tree allows")
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("proof shorter than the tree requires")
    return r


def consistency_proof(old_size: int, leaves: list[bytes]) -> list[bytes]:
    """Proof that the first `old_size` leaves are a prefix of this tree (RFC 9162 §2.1.4.1)."""
    n = len(leaves)
    if not 0 < old_size <= n:
        raise ValueError("old size must be in 1..size")
    if old_size == n:
        return []
    return _subproof(old_size, leaves, True)


def _subproof(m: int, leaves: list[bytes], b: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if b else [root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [root(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root(leaves[:k])]


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes,
                       proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2. True when the new tree extends the old one without change."""
    if old_size > new_size or old_size == 0:
        return False
    if old_size == new_size:
        return old_root == new_root and not proof
    proof = list(proof)
    if old_size & (old_size - 1) == 0:  # a power of two: the old root is the first node
        proof = [old_root] + proof
    if not proof:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = proof[0]
    for c in proof[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            while not (fn & 1) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root


class Frontier:
    """The right edge of an RFC 9162 tree: one root per perfect subtree, so appending is O(log n).

    A tree of size n is a sequence of perfect subtrees whose sizes are the binary digits of n, left
    to right, largest first. That is exactly RFC 6962's split — the left child is the largest power
    of two below n — so folding the subtree roots from the right gives the Merkle Tree Hash without
    the leaves. Appending a leaf merges equal-height subtrees, like incrementing a binary counter.
    """

    def __init__(self) -> None:
        self.size = 0
        self._stack: list[tuple[int, bytes]] = []   # (height, root), heights strictly decreasing

    def append(self, leaf: bytes) -> None:
        node, height = leaf, 0
        while self._stack and self._stack[-1][0] == height:
            _, left = self._stack.pop()
            node, height = node_hash(left, node), height + 1
        self._stack.append((height, node))
        self.size += 1

    def root(self) -> bytes:
        if not self._stack:
            return hashlib.sha256(b"").digest()
        acc = self._stack[-1][1]
        for _, left in reversed(self._stack[:-1]):
            acc = node_hash(left, acc)
        return acc
