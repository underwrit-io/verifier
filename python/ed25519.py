"""Ed25519, pure Python, after the RFC 8032 §6 reference. Standard library only.

SPDX-License-Identifier: MIT — Copyright (c) 2026 CAID LLC (Underwrit). This module is MIT, unlike the
rest of the package (proprietary, see LICENSE), because it is embedded verbatim in the `verify.py`
inside every evidence bundle and that script has to be copyable into anything, GPLv2 included.
See NOTICE. (The embed strips this docstring, so the notice the auditor actually receives lives in
`evidence._VERIFIER_HEAD`; `tests/test_packaging.py` checks it is there.)


Here because the evidence bundle's shipped `verify.py` must run with nothing installed, and
Python's standard library has no Ed25519.

**Signer and verifier must not be different implementations.** The module docstring used to claim
they could not disagree because "the same code signs on the data plane" — and then said, two lines
later, that `cryptography` is used when importable. Both halves were true and together they were
the problem: the data plane signs with `cryptography` (OpenSSL) and the shipped `verify.py` embeds
*this* code with the acceleration block stripped, because a bundle must verify with nothing
installed. So the two ends of the product's central claim ran different verification equations.

Ed25519 has a famously under-specified verification boundary — RFC 8032 permits both the
cofactorless equation `[s]B = R + [h]A` and the cofactored `[8][s]B = [8]R + [8][h]A`, and says
nothing binding about non-canonical encodings or small-order keys, so implementations legitimately
disagree on crafted signatures. A signature one end accepts and the other rejects is, for this
product, an evidence pack that verifies for the issuer and fails for the auditor, or the reverse.

So `verify` here is deliberately **strict**, at the intersection of what the strict implementations
accept: canonical encodings for both `A` and `R` (a `y` at or above `p` is refused rather than
reduced), `s < q`, small-order `A` and `R` refused, and the cofactored equation, which accepts
everything the cofactorless one does on honest signatures and refuses the crafted cases where they
part. `tests/test_signatures.py` runs the RFC 8032 vectors and a corpus of edge cases through this
code and through `cryptography` and requires the same verdict for every one — the only way to make
"signer and verifier cannot disagree" a fact rather than a sentence.

Slow — a few milliseconds per operation — which is fine for a checkpoint every few seconds and a
handful of signatures per bundle. Not constant-time; do not use it for anything where the private
key's timing could be observed by an adversary, which a data plane signing its own checkpoints is
not. `sign` is used only where `cryptography` is absent.
"""

from __future__ import annotations

import hashlib
import secrets

_p = 2 ** 255 - 19
_q = 2 ** 252 + 27742317777372353535851937790883648493
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def _inv(x: int) -> int:
    return pow(x, _p - 2, _p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x


_By = 4 * _inv(5) % _p
_Bx = _xrecover(_By)
_B = (_Bx % _p, _By % _p, 1, (_Bx * _By) % _p)  # extended coordinates (X, Y, Z, T)
_IDENT = (0, 1, 1, 0)


def _add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _p
    b = (y1 + x1) * (y2 + x2) % _p
    c = t1 * 2 * _d * t2 % _p
    dd = z1 * 2 * z2 % _p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _p, g * h % _p, f * g % _p, e * h % _p)


def _mul(s: int, P):
    Q = _IDENT
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _encode_point(P) -> bytes:
    x, y, z, _ = P
    zi = _inv(z)
    x, y = x * zi % _p, y * zi % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode_point(s: bytes):
    """A point from its 32-byte encoding, refusing every non-canonical spelling.

    `y >= p` is the non-canonical case: the encoding is a little-endian integer below 2^255, so
    values in `[p, 2^255)` name a point that already has a canonical encoding. An implementation
    that reduces mod p accepts a second spelling of the same key or nonce; a strict one refuses it.
    That difference is one of the two places Ed25519 implementations are known to part company.
    """
    if len(s) != 32:
        raise ValueError("bad point length")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _p:
        raise ValueError("non-canonical point encoding")
    x = _xrecover(y)
    if x & 1 != sign:
        x = _p - x
    P = (x, y, 1, x * y % _p)
    if not _on_curve(P):
        raise ValueError("point not on curve")
    return P


def _on_curve(P) -> bool:
    x, y, z, t = P
    return (z % _p != 0 and x * y % _p == z * t % _p
            and (y * y - x * x - z * z - _d * t * t) % _p == 0)


def _equal(P, Q) -> bool:
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    return (x1 * z2 - x2 * z1) % _p == 0 and (y1 * z2 - y2 * z1) % _p == 0


# The order of the prime-order subgroup times the cofactor. A point P is of small order exactly
# when [8]P is the identity; such a key or nonce contributes nothing to the equation, which is how
# a signature can be made to verify under a key nobody holds.
def _small_order(P) -> bool:
    Q = _add(P, P)
    Q = _add(Q, Q)
    Q = _add(Q, Q)
    return Q[0] % _p == 0 and (Q[1] - Q[2]) % _p == 0


def _secret_expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def generate_seed() -> bytes:
    return secrets.token_bytes(32)


def public_key(seed: bytes) -> bytes:
    a, _ = _secret_expand(seed)
    return _encode_point(_mul(a, _B))


def sign(seed: bytes, msg: bytes) -> bytes:
    a, prefix = _secret_expand(seed)
    A = _encode_point(_mul(a, _B))
    r = int.from_bytes(_sha512(prefix, msg), "little") % _q
    R = _encode_point(_mul(r, _B))
    h = int.from_bytes(_sha512(R, A, msg), "little") % _q
    s = (r + h * a) % _q
    return R + int.to_bytes(s, 32, "little")


def verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
    """Strict Ed25519 verification. See the module docstring for why every check below is here."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    try:
        A = _decode_point(pub)        # refuses a non-canonical public key
        R = _decode_point(sig[:32])   # refuses a non-canonical R
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _q:                       # refuses a malleable S
        return False
    if _small_order(A) or _small_order(R):
        return False
    h = int.from_bytes(_sha512(sig[:32], pub, msg), "little") % _q
    # Cofactored: [8][s]B == [8]R + [8][h]A. Identical to the cofactorless equation for any
    # signature either end would produce, and the tie-break where the two forms disagree.
    left, right = _mul(s, _B), _add(R, _mul(h, A))
    for _ in range(3):
        left, right = _add(left, left), _add(right, right)
    return _equal(left, right)


# --- optional acceleration -----------------------------------------------------------------

try:  # pragma: no cover - exercised where cryptography is installed
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey as _Priv, Ed25519PublicKey as _Pub)
    from cryptography.exceptions import InvalidSignature as _Invalid

    def fast_sign(seed: bytes, msg: bytes) -> bytes:
        return _Priv.from_private_bytes(seed).sign(msg)

    def fast_verify(pub: bytes, msg: bytes, sig: bytes) -> bool:
        try:
            _Pub.from_public_bytes(pub).verify(sig, msg)
            return True
        except (_Invalid, ValueError):
            return False

    HAVE_FAST = True
except ImportError:  # pragma: no cover
    fast_sign, fast_verify, HAVE_FAST = sign, verify, False
