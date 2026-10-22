#!/usr/bin/env python3
"""Verify this evidence pack. Standard library only; needs nothing from the system that made it.

    python3 verify.py                         # from inside the bundle directory
    UNDERWRIT_PUBLIC_KEY=<base64> python3 verify.py   # and check origin against a key you obtained elsewhere

Checks, each independent of the others:

  1. Every file matches the SHA-256 recorded in manifest.json, so nothing has been edited.
  2. Every audit entry's hash is the SHA-256 of its predecessor's hash plus its own contents, so no
     entry has been altered and none has been reordered.
  3. (format 2) The checkpoint's Ed25519 signature verifies under the key named in the manifest,
     and every entry's inclusion proof leads to the checkpoint's root — so each entry sits where
     the log said it did, in a tree of the size the log signed.
  4. (format 2) The manifest's Ed25519 signature verifies under the same key.

It also prints the pack's build statement — which edition and licence produced it, and whether that
code is the release Underwrit signed — and warns on a modified build or an install over its limit.
That is reported, not failed, unless you pass --require release.

What this cannot prove: that the record is complete (a subset cannot show what was left out), and
origin, unless you obtained the public key from the issuer yourself — the copy in this bundle only
shows the bundle agrees with itself. Set UNDERWRIT_PUBLIC_KEY to the issuer's published key to check that.

SPDX-License-Identifier: MIT
Copyright (c) 2026 Underwrit

This script is MIT, including the Ed25519, Merkle and RFC 3161 code embedded below — deliberately,
although the rest of Underwrit is proprietary. MIT is compatible with everything, GPLv2
included, so you can paste this into whatever you already use to audit things. You owe nobody a
notice for doing it. A verifier you are not free to embed is not much of a verifier.
"""
import base64, hashlib, hmac, json, os, sys
from pathlib import Path

HERE = Path(__file__).parent
GENESIS = "0" * 64

# ---- Ed25519 (RFC 8032), from underwrit/ed25519.py ----

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


def _pure_verify(pub, msg, sig):
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



try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey as _Pub
    from cryptography.exceptions import InvalidSignature as _Invalid

    def ed25519_verify(pub, msg, sig):
        try:
            _Pub.from_public_bytes(pub).verify(sig, msg)
        except Exception:
            return False
        # Both must accept. They are required to agree by the issuer's test suite; if they do not
        # agree here, this bundle is being read by an implementation pair that has never been
        # checked against each other, and refusing is the only honest answer.
        return _pure_verify(pub, msg, sig)

    ED25519_BACKEND = "cryptography + embedded (both must accept)"
except ImportError:
    ed25519_verify = _pure_verify
    ED25519_BACKEND = "embedded pure-Python (RFC 8032, strict)"

# ---- Merkle proofs (RFC 9162), from underwrit/merkle.py ----

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
# ---- RFC 3161 response reader, from underwrit/tsa.py ----
SHA256_OID = bytes.fromhex("608648016503040201")  # 2.16.840.1.101.3.4.2.1


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def timestamp_request(digest: bytes, nonce: int | None = None, cert_req: bool = True) -> bytes:
    """A DER TimeStampReq (RFC 3161 §2.4.1) for a SHA-256 imprint."""
    alg = _tlv(0x30, _tlv(0x06, SHA256_OID) + b"\x05\x00")
    imprint = _tlv(0x30, alg + _tlv(0x04, digest))
    body = _tlv(0x02, b"\x01") + imprint
    if nonce is not None:
        nb = nonce.to_bytes(16, "big").lstrip(b"\x00") or b"\x00"
        if nb[0] & 0x80:
            nb = b"\x00" + nb
        body += _tlv(0x02, nb)
    if cert_req:
        body += _tlv(0x01, b"\xff")
    return _tlv(0x30, body)


# --------------------------------------------------------------------------------------------
# Minimal DER reader: enough to find TSTInfo inside a TimeStampResp.


def _read(data: bytes, i: int) -> tuple[int, bytes, int]:
    """(tag, value, next index) at position i. Raises ValueError on truncated or absurd input."""
    if i + 2 > len(data):
        raise ValueError("truncated DER")
    tag = data[i]
    i += 1
    ln = data[i]
    i += 1
    if ln & 0x80:
        k = ln & 0x7F
        if k == 0 or k > 4 or i + k > len(data):
            raise ValueError("bad DER length")
        ln = int.from_bytes(data[i:i + k], "big")
        i += k
    if i + ln > len(data):
        raise ValueError("DER value runs past the end")
    return tag, data[i:i + ln], i + ln


def _children(body: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(body):
        tag, val, i = _read(body, i)
        out.append((tag, val))
    return out


TSTINFO_OID = bytes.fromhex("2A864886F70D010910010" + "4")  # 1.2.840.113549.1.9.16.1.4


def _find_tstinfo(resp: bytes) -> bytes | None:
    """The TSTInfo **that the token signs**, reached structurally.

    This used to scan the response bytes for the id-ct-TSTInfo OID and take the first hit. A TSA —
    or anyone on the wire, since `UNDERWRIT_TSA_URL` is commonly plain HTTP — could put a second,
    unsigned TSTInfo earlier in the DER (SignedData's `certificates` field precedes
    `encapContentInfo`), and OpenSSL would read the signed one while this read the decoy. Both gates
    in `stamp()` — the imprint and the nonce — then checked attacker-chosen bytes, so a replayed
    token from any year could be dressed in today's imprint and this request's nonce and recorded as
    a fresh independent clock. Nothing downstream would have noticed.

    So the path is walked rather than searched: TimeStampResp → timeStampToken (ContentInfo) →
    SignedData → encapContentInfo → eContent. A response carrying anything else where the signed
    content should be is refused.
    """
    _, resp_body, _ = _read(resp, 0)
    for tag, value in _children(resp_body):
        if tag != 0x30:
            continue          # PKIStatusInfo; the token is the SEQUENCE after it
        content_info = _children(value)
        if len(content_info) < 2 or content_info[0][0] != 0x06:
            continue
        signed_data = content_info[1][1]
        if content_info[1][0] & 0xE0 != 0xA0:
            continue          # [0] EXPLICIT
        for stag, sval in _children(signed_data):
            if stag != 0x30:
                continue      # digestAlgorithms is a SET; SignedData itself is this SEQUENCE
            fields = _children(sval)
            # SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo SEQUENCE, … }
            for ftag, fval in fields:
                if ftag != 0x30:
                    continue
                kids = _children(fval)
                if len(kids) == 2 and kids[0] == (0x06, TSTINFO_OID) and kids[1][0] & 0xE0 == 0xA0:
                    inner = kids[1][1]
                    while inner and inner[0] == 0x04:
                        _, inner, _ = _read(inner, 0)
                    return inner if inner and inner[0] == 0x30 else None
            break
    return None


def parse_tsr(resp: bytes) -> dict:
    """{ok, status, genTime, imprint (hex), serial, hashAlg} from a TimeStampResp. Raises ValueError
    on input that is not DER at all."""
    tag, body, _ = _read(resp, 0)
    kids = _children(body)
    status_kids = _children(kids[0][1]) if kids else []
    status = int.from_bytes(status_kids[0][1], "big") if status_kids else -1
    out = {"ok": status in (0, 1), "status": status, "genTime": None, "imprint": None,
           "serial": None, "hashAlg": None, "nonce": None}
    if not out["ok"] or len(kids) < 2:
        return out
    tst = _find_tstinfo(resp)
    if not tst:
        out["ok"] = False
        return out
    fields = _children(_read(tst, 0)[1])
    # TSTInfo ::= SEQUENCE { version, policy OID, messageImprint, serialNumber, genTime, ... }
    for idx, (t, v) in enumerate(fields):
        if t == 0x30 and out["imprint"] is None and idx >= 2:
            sub = _children(v)
            if len(sub) == 2 and sub[1][0] == 0x04:
                out["imprint"] = sub[1][1].hex()
                alg = _children(sub[0][1])
                oid = alg[0][1] if alg and alg[0][0] == 0x06 else b""
                out["hashAlg"] = "sha256" if oid == SHA256_OID else oid.hex()
        elif t == 0x02 and out["imprint"] is not None and out["serial"] is None:
            out["serial"] = int.from_bytes(v, "big")
        elif t == 0x02 and out["genTime"] is not None and out["nonce"] is None:
            # TSTInfo ::= ... genTime, accuracy?, ordering?, nonce?, ... — the first INTEGER after
            # genTime is the nonce. RFC 3161 §2.4.2: if the request carried one, the response MUST
            # carry the same value, and it is the only thing in the exchange that proves this token
            # was minted for this request rather than replayed from a recording.
            out["nonce"] = int.from_bytes(v, "big")
        elif t == 0x18 and out["genTime"] is None:  # GeneralizedTime YYYYMMDDHHMMSS[.f]Z
            s = v.decode("ascii")
            out["genTime"] = f"{s[0:4]}-{s[4:6]}-{s[6:8]}T{s[8:10]}:{s[10:12]}:{s[12:14]}Z"
    return out




def entry_hash(previous, payload):
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(previous.encode("utf-8") + body).hexdigest()


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def note_body(origin, size, root, extra=()):
    """The signed bytes of a note. A seal note carries lines after the root; a checkpoint does not,
    and for it this is byte-for-byte what it always was."""
    return "\n".join([origin, str(size), base64.b64encode(root).decode(), *extra]) + "\n"


def _cosigned_by(parsed, body, wkeys):
    """(witness name, time) for the first pinned key that cosigned this note, else ("", 0)."""
    for wkey in wkeys:
        try:
            wpub = base64.b64decode(wkey)
        except Exception:  # noqa: BLE001
            continue
        for nm, kh, rest in parsed["signatures"]:
            if nm == parsed["origin"] or len(rest) != 72:
                continue
            if kh != hashlib.sha256(nm.encode() + b"\n\x04" + wpub).digest()[:4].hex():
                continue
            t = int.from_bytes(rest[:8], "big")
            if ed25519_verify(wpub, f"cosignature/v1\ntime {t}\n{body}".encode(), rest[8:]):
                return nm, t
    return "", 0


def scope_of(detail):
    """The session an entry belongs to: the first of these `detail` keys that is set."""
    for k in ("sessionId", "runId", "subjectId", "requestId"):
        v = detail.get(k) if isinstance(detail, dict) else None
        if isinstance(v, str) and v:
            return v
    return ""


def scope_leaf(scope, seq, hash_hex):
    return leaf_hash(f"underwrit-scopes\n{scope}\n{int(seq)}\n{hash_hex}".encode("utf-8"))


def parse_scopes_line(extra):
    """{count, root} from a checkpoint's one permitted extension line; None when there is none."""
    if not extra:
        return None
    if len(extra) != 1:
        raise ValueError("a checkpoint carries at most one extension line")
    parts = extra[0].split(" ")
    if len(parts) != 3 or parts[0] != "underwrit-scopes" or not parts[1].isdigit():
        raise ValueError("the only extension line a checkpoint may carry is `underwrit-scopes <count> <root>`")
    root = base64.b64decode(parts[2])
    if len(root) != 32:
        raise ValueError("the scopes root is 32 bytes")
    return {"count": int(parts[1]), "root": root}


def parse_seal_note(note):
    """A seal note's signed fields. Read from the note, never from the JSON beside it."""
    parsed = parse_note(note)
    if not parsed["origin"].startswith("underwrit-seal/"):
        raise ValueError("origin does not name a seal")
    fields = {}
    for line in parsed["extra"]:
        name, _, value = line.partition(" ")
        if name in fields:
            raise ValueError(f"a seal note states {name} twice")
        fields[name] = value
    if set(fields) != {"archive", "epoch"}:
        raise ValueError("a seal note's body is the archive and the epoch, and nothing else")
    archive = fields["archive"].lower()
    if len(archive) != 64 or any(ch not in "0123456789abcdef" for ch in archive):
        raise ValueError("a seal note's archive digest must be 64 hex characters")
    return {**parsed, "archiveSha256": archive, "epoch": int(fields["epoch"])}


def parse_note(note):
    body, _, sigs = note.partition("\n\n")
    lines = body.split("\n")
    if len(lines) < 3:
        raise ValueError("signed note is too short")
    root = base64.b64decode(lines[2])
    if len(root) != 32:
        # The issuer's parser refuses this; so must the one shipped in the bundle. Two
        # implementations of one format disagreeing is the failure the strictness work exists to
        # remove, and on a post-seal pack — where no inclusion proof constrains the root — this
        # verifier was reporting "signature verified" for a note the issuer calls malformed.
        raise ValueError("a note's root is 32 bytes")
    out = {"origin": lines[0], "size": int(lines[1]), "root": root,
           "extra": tuple(lines[3:]), "signatures": []}
    for line in sigs.splitlines():
        if line.startswith("\u2014 "):
            _, name, blob = line.split(" ", 2)
            raw = base64.b64decode(blob)
            out["signatures"].append((name, raw[:4].hex(), raw[4:]))
    return out


def build_lines(build):
    """(text, is_warning) lines for a pack's build statement. Never raises on a malformed one."""
    out = []
    try:
        b = build.get("build") if isinstance(build.get("build"), dict) else {}
        status = str(b.get("status") or "unknown")
        out.append((f"Underwrit {build.get('version') or '?'}, {build.get('edition') or '?'} edition, licence "
                    f"{build.get('licence') or 'none'}, {status} build (code {str(b.get('hash') or '-')[:16]})", False))
        if status in ("modified", "unsigned", "unknown"):
            out.append((f"modified build: {b.get('reason') or 'its code is not the release Underwrit signed'}", True))
        elif status == "source":
            out.append(("not a release build: it ran from a source checkout", True))
        cp = build.get("controlPlane") if isinstance(build.get("controlPlane"), dict) else None
        for who, st in (("this install", build), ("its control plane", cp)):
            if not st:
                continue
            cb = st.get("build") if isinstance(st.get("build"), dict) else {}
            if st is cp and cb.get("status") in ("modified", "unsigned"):
                out.append((f"modified build: {who} runs code that is not the release Underwrit signed", True))
            if st.get("overLimit") is True:
                lim, use = st.get("limits") or {}, st.get("usage") or {}
                counts = f"{who} counts {use.get('tenants')} team(s) and {use.get('dataPlanes')} data plane(s)"
                if lim.get("source") == "free" or (st.get("licence") or "none") == "none":
                    out.append((f"exceeds free limit: {counts}; the free edition allows one of each", True))
                else:
                    out.append((f"exceeds its licence: {counts}, licensed for {lim.get('tenants')} and "
                                f"{lim.get('dataPlanes')}", True))
    except (AttributeError, TypeError, ValueError):
        out.append(("the build statement is malformed", True))
    return out


def _require() -> set:
    """--require a,b or UNDERWRIT_REQUIRE: artefacts whose absence is a failure, not a notice."""
    want = set()
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a.startswith("--require="):
            want.update(x.strip() for x in a.split("=", 1)[1].split(",") if x.strip())
        elif a == "--require" and i + 1 < len(argv):
            want.update(x.strip() for x in argv[i + 1].split(",") if x.strip())
    want.update(x.strip() for x in os.environ.get("UNDERWRIT_REQUIRE", "").split(",") if x.strip())
    bad = want - {"signature", "checkpoint", "witness", "timestamp", "release"}
    if bad:
        raise SystemExit(f"unknown --require item(s): {', '.join(sorted(bad))} "
                         f"(choose from signature, checkpoint, witness, timestamp, release)")
    return want


def main():
    require = _require()
    pinned = os.environ.get("UNDERWRIT_PUBLIC_KEY", "").strip()
    wkeys = [k.strip() for k in os.environ.get("UNDERWRIT_WITNESS_KEY", "").split(",") if k.strip()]
    # A pinned key is a demand, not a hint: pinning the log key requires a signed, checkpointed
    # bundle, and pinning a witness key requires a cosignature. Otherwise a bundle stripped back to
    # format 1 would "verify" with every pin silently ignored.
    if pinned:
        require |= {"signature", "checkpoint"}
    if wkeys:
        require |= {"witness"}

    try:
        manifest = json.loads((HERE / "manifest.json").read_text())
    except FileNotFoundError:
        print("FAILED: manifest.json is missing — this is not a complete bundle")
        return 1
    except ValueError:
        print("FAILED: manifest.json is not valid JSON")
        return 1
    if manifest.get("format", 1) not in (1, 2, 3, 4):
        print(f"FAILED: this verifier understands formats 1 to 4, not {manifest.get('format')}")
        return 1
    problems = []

    for name, expected in sorted((manifest.get("files") or {}).items()):
        try:
            actual = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        except FileNotFoundError:
            problems.append(f"{name}: listed in the manifest but missing from the bundle")
            continue
        if actual != expected:
            problems.append(f"{name}: content does not match its recorded digest")
    for name in ("evidence.json", "verify.py"):
        if name not in (manifest.get("files") or {}):
            problems.append(f"{name}: not covered by the manifest")

    try:
        pack = json.loads((HERE / "evidence.json").read_text())
        entries = pack["auditEntries"]
        assert isinstance(entries, list)
    except (FileNotFoundError, ValueError, KeyError, AssertionError):
        print("FAILED: evidence.json is missing or malformed")
        return 1
    # The `audit.redact` entries present here, by the sequence each authorises. A redaction skips
    # the content check, so the flag alone would let a producer rewrite everything erasure leaves
    # readable — action, outcome, environment, time — and still pass. The authorising entry is
    # hashed normally and carries a digest of exactly those fields, so it cannot be forged without
    # breaking a hash this script does recompute.
    explained = {}
    for entry in entries:
        if not isinstance(entry, dict) or entry.get("action") != "audit.redact" or entry.get("redacted"):
            continue
        d = entry.get("detail")
        if isinstance(d, dict) and isinstance(d.get("redactedSeq"), int):
            explained[d["redactedSeq"]] = str(d.get("survivingDigest") or "")

    def commit_at(value):
        # Never raises. `at` is a number in a well-formed pack and anything at all in a tampered
        # one, and a verifier that throws on the tampered case hands the auditor "the tool is
        # broken" instead of "entry 1 was edited" — a one-character way to make a forgery read as a
        # tooling problem. `OverflowError` is in the net because a pack is JSON and JSON integers
        # are unbounded: `float(10**400)` raises. For anything that parses this is the float it
        # always was, so every digest already recorded still verifies.
        try:
            return float(value)
        except (TypeError, ValueError, OverflowError):
            return "unparseable:" + repr(value)

    def surviving(entry):
        body = {"at": commit_at(entry["at"]), "action": str(entry["action"] or ""),
                "outcome": str(entry["outcome"] or ""), "environment": str(entry["environment"] or ""),
                "prev_hash": str(entry["prevHash"] or ""), "hash": str(entry["hash"] or "")}
        if entry.get("scopePrev"):
            # Format 4: the session link survives an erasure, so the authorisation commits to it.
            body["scope_prev"] = str(entry["scopePrev"])
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()

    redactions = 0
    for entry in entries:
        try:
            if entry.get("redacted"):
                # An erasure, not an edit. The content is gone, so there is nothing to recompute;
                # the entry's place in the log and its recorded hash are still covered by the
                # Merkle proof and the signed checkpoint below. What is checked is that the entry
                # actually looks erased — "redacted" must not be a way to show arbitrary content
                # and skip the hash check.
                redactions += 1
                # The same set `chain.REDACTED_FIELDS` blanks. `actorId` is among them — it can
                # hold `oidc:<sub>`, which is an email address at many providers. Leaving it out
                # here meant the pack's own segment verdict said "broken" while the verifier a
                # regulator runs said "OK", with the erased address still in the file.
                leftover = [k for k in ("actorId", "sourceIp") if entry.get(k)]
                if entry.get("detail"):
                    leftover.append("detail")
                if not all(entry.get(k) == "[redacted]" for k in ("actor", "target", "reason")):
                    leftover.append("actor/target/reason")
                if leftover:
                    problems.append(
                        f"audit entry seq {entry['seq']}: marked redacted but still carries "
                        f"{', '.join(leftover)} — that is not what a redaction leaves behind")
                elif entry["seq"] not in explained:
                    problems.append(
                        f"audit entry seq {entry['seq']}: marked redacted with no `audit.redact` "
                        "entry in this record authorising it. A redaction skips the content check, "
                        "so an unexplained one is how an edited row would be made to verify clean")
                elif explained[entry["seq"]] != surviving(entry):
                    problems.append(
                        f"audit entry seq {entry['seq']}: the fields this redaction left readable "
                        "are not the ones the erasure authorised — its action, outcome, environment "
                        "or time has been changed since")
                continue
            payload = {
                "at": entry["at"], "actor": entry["actor"], "actor_id": entry["actorId"],
                "action": entry["action"], "environment": entry["environment"],
                "target": entry["target"], "outcome": entry["outcome"], "reason": entry["reason"],
                # `detail` is hashed as the OBJECT, not as a JSON string of it.
                "detail": entry["detail"], "source_ip": entry["sourceIp"],
            }
            if entry.get("scopePrev"):
                # Format 4's session link is part of what the entry's hash covers.
                payload["scope_prev"] = entry["scopePrev"]
            prev = entry.get("prevHash") or ""
            if len(prev) != 64:
                # Not `prev or GENESIS`: an honest entry always records a 64-character predecessor,
                # so an empty one is a row this log did not write, and letting it verify as though
                # it sat at the genesis handed a forged entry a position it could satisfy.
                problems.append(f"audit entry seq {entry['seq']}: records no predecessor hash")
            elif entry_hash(prev, payload) != entry["hash"]:
                named = []
                try:
                    recorded = json.loads(entry.get("fieldDigests") or "{}")
                except ValueError:
                    recorded = {}
                for field, want in sorted(recorded.items()):
                    v = entry.get(field)
                    if field == "at":
                        c = commit_at(v)
                        raw = ("%.6f" % c) if isinstance(c, float) else c
                    else:
                        # Not `str(v or "")`. A pack is JSON, so 0, false, null, [] and {} all
                        # collapsed to "" — and `environment` is genuinely "" on every audit.redact
                        # and audit.seal entry, so editing one of those to 0 left its digest
                        # matching while the hash broke, and this verifier then claimed, positively
                        # and wrongly, that the change was in one of the six uncommitted fields.
                        raw = "" if v is None else str(v)
                    if hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12] != want:
                        named.append(field)
                if named:
                    where = (f": at least {', '.join(named)} changed (the six identifying fields "
                             "carry no commitment, so there may be more)")
                elif recorded:
                    where = (": the change is in actor, actorId, target, reason, detail or "
                             "sourceIp, which carry no per-field commitment by design")
                else:
                    # An older pack, from before this pack format carried them. Saying which field
                    # would be a guess, and a verifier that guesses is the thing this format is
                    # arranged not to be.
                    # Per *entry*, not per pack: after an upgrade a pack legitimately mixes rows
                    # sealed before the digests existed with rows sealed after.
                    where = " (this entry records no per-field digests, so which field cannot be said)"
                problems.append(
                    f"audit entry seq {entry['seq']}: contents do not match its hash{where}")
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            problems.append(f"audit entry {entry.get('seq', '?') if isinstance(entry, dict) else '?'}: malformed ({type(exc).__name__})")
    if redactions:
        print(f"redactions: {redactions} entr{'y' if redactions == 1 else 'ies'} erased under a "
              "retention or erasure request. Their position and hash are still proven; their "
              "content no longer exists to check.")

    # Order. The file is read top to bottom by people, so it must be in the log's order: an entry
    # moved within the file keeps its own hash and proof, and nothing else would notice.
    _seqs = [e.get("seq") for e in entries if isinstance(e, dict)]
    if any(not isinstance(a, int) or not isinstance(b, int) or b <= a for a, b in zip(_seqs, _seqs[1:])):
        _bad = next((b for a, b in zip(_seqs, _seqs[1:])
                     if not isinstance(a, int) or not isinstance(b, int) or b <= a), None)
        problems.append(f"order: entries are not in sequence order (seq {_bad} comes after a later or "
                        "equal one); the record reads as a different order of events than the log's")

    # Session links (format 4). Every entry of the pack's own session records the hash of that
    # session's previous entry, so an entry removed from the middle leaves the next one pointing
    # at something this pack does not contain.
    subject_id = str((pack.get("subject") or {}).get("id") or "")
    session_entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        derived = "" if entry.get("redacted") else scope_of(entry.get("detail"))
        carried = str(entry.get("scope") or "")
        if derived and carried and derived != carried:
            problems.append(f"audit entry seq {entry.get('seq')}: says it belongs to {carried!r} but its "
                            f"own contents name {derived!r}")
        if (derived or carried) == subject_id and subject_id:
            session_entries.append(entry)
    linked = sum(1 for e in session_entries if e.get("scopePrev"))
    last = None
    for entry in session_entries:
        link = entry.get("scopePrev")
        if link:
            want = last["hash"] if last else GENESIS
            if link != want:
                problems.append(
                    f"session: entry seq {entry.get('seq')} follows an entry of this session that is not "
                    f"in this pack (it links to {str(link)[:12]}…, the pack's previous one is "
                    f"{(last['hash'][:12] + '…') if last else 'none, so it should be the session start'}). "
                    "An entry has been removed from the middle of the record")
        last = entry
    if session_entries:
        if linked == len(session_entries):
            print(f"session: all {linked} entries of {subject_id} link to the one before — none is "
                  "missing from between them")
        elif linked:
            print(f"session: {linked} of {len(session_entries)} entries of {subject_id} carry a session "
                  "link; the earlier ones predate it, and a removal among those would not show here")
        else:
            print(f"session: no entry of {subject_id} carries a session link (written before format 4, "
                  "or with UNDERWRIT_SESSION_LINKS=off) — an entry removed from the middle would not "
                  "be detected")
    other = sorted({str(e.get("scope") or "") for e in entries if isinstance(e, dict)} - {subject_id, ""})
    if other:
        print(f"session: {len(other)} other scope(s) appear in this pack; their completeness is not "
              "checked here, only that of the pack's own subject")

    # Which format was read, said out loud. This verifier accepts three of them and they do not
    # check the same things — a format-1 pack has no checkpoint and no inclusion proofs, so "OK"
    # over one means considerably less than "OK" over a format-3 pack, and a reader who cannot see
    # which they are holding cannot tell the difference. Anything that changes the strength of the
    # verdict belongs in the output.
    _fmt = manifest.get("format", 1)
    print(f"format: {_fmt} — " + {
        1: "chain and manifest digests only; no checkpoint, no inclusion proofs",
        2: "chain, signed checkpoint and an inclusion proof for every entry",
        3: "as format 2, plus erasures that stay in the record and a consistency proof",
        4: "as format 3, plus session links and committed session heads, so a session's missing entries show",
    }.get(_fmt, "unrecognised, but within the range this verifier accepts"))

    # --- format 2: checkpoint, proofs, signatures ----------------------------------------------
    sigs = manifest.get("signatures") or []
    ed = next((s for s in sigs if isinstance(s, dict) and s.get("alg") == "ed25519"), None)
    if "signature" in require and not ed:
        problems.append("origin: no Ed25519 manifest signature, and one is required (a key is pinned)")
    pub = None
    if ed:
        pub = base64.b64decode(ed["publicKey"])
        if pinned:
            pins = [base64.b64decode(k.strip()) for k in pinned.split(",") if k.strip()]
            if pub in pins:
                print(f"origin: verified against the pinned key ({ed['keyId']})")
            else:
                problems.append("origin: no pinned key matches the key that signed this bundle")
        else:
            print(f"origin: key {ed['keyId']} ({ed.get('origin', '')}) — shown, not verified. "
                  "Obtain the issuer's key and set UNDERWRIT_PUBLIC_KEY to check origin.")
        if ed25519_verify(pub, canonical(manifest["files"]), base64.b64decode(ed["signature"])):
            print("manifest: signature verified")
        else:
            problems.append("manifest: Ed25519 signature does not verify")
    else:
        print("origin: no Ed25519 signature (format 1 bundle, or an unsigned data plane)")

    proven = 0
    has_checkpoint = (HERE / "checkpoint").exists() and bool(pack.get("merkle"))
    if "checkpoint" in require and not has_checkpoint:
        problems.append("checkpoint: none in this bundle, and one is required (a key is pinned)")
    if "witness" in require and not has_checkpoint:
        problems.append("witness: no checkpoint to carry a cosignature, and one is required")
    if "timestamp" in require and not (HERE / "timestamps" / "checkpoint.tsr").exists():
        problems.append("timestamp: no RFC 3161 token in this bundle, and one is required")
    if has_checkpoint:
        note = (HERE / "checkpoint").read_text()
        try:
            cp = parse_note(note)
        except (ValueError, IndexError, TypeError) as exc:
            print(f"FAILED: the checkpoint note is malformed ({type(exc).__name__})")
            return 1
        body = note_body(cp["origin"], cp["size"], cp["root"], cp["extra"]).encode()
        ok_sig = False
        if pub is not None:
            want = hashlib.sha256(cp["origin"].encode() + b"\n\x01" + pub).digest()[:4].hex()
            ok_sig = any(n == cp["origin"] and kh == want and ed25519_verify(pub, body, s)
                         for n, kh, s in cp["signatures"])
        if ok_sig:
            print(f"checkpoint: signature verified (size {cp['size']})")
        else:
            problems.append("checkpoint: signature does not verify under the bundle's key")
        if cp["root"].hex() != pack["merkle"]["root"] or cp["size"] != pack["merkle"]["size"]:
            problems.append("checkpoint: does not match the tree the pack describes")
        # Witness cosignatures, if any: each is a second party's statement that this is the
        # history it saw. Pin one key per witness in UNDERWRIT_WITNESS_KEY (comma-separated); every
        # pinned key must verify a cosignature on this checkpoint.
        cosigs = [(n, kh, rest) for n, kh, rest in cp["signatures"] if n != cp["origin"] and len(rest) == 72]
        # Whether the witness requirement is satisfied is decided AFTER the consistency branch
        # below. A bundle taken between cosignatures has no cosignature on *this* checkpoint and is
        # perfectly honest; refusing it outright meant the only auditor who pins a witness key —
        # the one doing the strongest check available — got FAILED on every such pack.
        # Only a cosignature verified against a pinned key counts. A signature line is just text
        # in a file: appending `— some-witness <72 bytes of base64>` and re-signing the manifest
        # satisfied `--require witness` without anybody having signed anything.
        witness_satisfied = False
        if cosigs and wkeys:
            import datetime
            for wkey in wkeys:
                wpub = base64.b64decode(wkey)
                ok_w = None
                for n, kh, rest in cosigs:
                    want = hashlib.sha256(n.encode() + b"\n\x04" + wpub).digest()[:4].hex()
                    t = int.from_bytes(rest[:8], "big")
                    msg = f"cosignature/v1\ntime {t}\n".encode() + body
                    if kh == want and ed25519_verify(wpub, msg, rest[8:]):
                        ok_w = (n, t)
                        break
                if ok_w:
                    witness_satisfied = True
                    print(f"witness: {ok_w[0]} cosigned this checkpoint at "
                          f"{datetime.datetime.utcfromtimestamp(ok_w[1]).isoformat()}Z — the history up to size "
                          f"{cp['size']} is the one it saw")
                else:
                    problems.append(f"witness: the pinned witness key {wkey[:8]}… does not verify any cosignature on this checkpoint")
            if len(wkeys) > 1 and not problems:
                print(f"witness: {len(wkeys)} independent witnesses agree on this history")
        elif cosigs:
            print(f"witness: cosigned by {', '.join(n for n, _, _ in cosigs)} — set UNDERWRIT_WITNESS_KEY to check it")
        else:
            print("witness: none — completeness rests on the log alone; a witness cosignature is what "
                  "would show this history is the one a second party saw")
        # A witness that cosigned an EARLIER size: the pack ships a consistency proof, and this is
        # the only check in a bundle that can catch a shortened or rewritten history. A rollback
        # produces a tree the earlier cosigned root cannot be proven consistent with.
        wit = (pack["merkle"].get("witnessed") or {}) if isinstance(pack["merkle"].get("witnessed"), dict) else {}
        if wit.get("consistencyError"):
            problems.append(f"witness: {wit['consistencyError']}")
        elif wit.get("supersededBySeal"):
            # A seal ends one tree and starts another, so the witnessed size is legitimately beyond
            # this one — IF a seal actually closed the witnessed tree, and IF that tree is one a
            # witness really attested.
            #
            # A seal explains a DISCONTINUITY. It says nothing whatever about the entries in this
            # pack, which are in the epoch AFTER it. Treating it as satisfying a pinned witness key
            # made a witnessed seal a permanent excuse for every later rollback: an operator could
            # rewind their own record of what the witness saw to the epoch boundary, delete anything
            # the witness had cosigned since, and ship a pack that said "the check a rollback cannot
            # pass". The seal is checked here; the pinned-witness requirement is not satisfied by it.
            seal = wit["supersededBySeal"]
            lineage = [x for x in (wit.get("sealLineage") or []) if isinstance(x, dict)][:64]
            want_size, want_root = int(wit.get("size") or 0), str(wit.get("root") or "")
            settled = False

            # First: is the claimed witnessed head one a witness actually cosigned? Everything in
            # `wit` is written by the producer, so without this the head being reconciled against
            # is whichever past tree suits them.
            head_ok, head_by = False, ""
            if wkeys and want_root:
                try:
                    head = parse_note(str(wit.get("cosignedNote") or ""))
                    hbody = note_body(head["origin"], head["size"], head["root"], head["extra"])
                    if head["size"] == want_size and head["root"].hex() == want_root:
                        head_ok, head_by = _cosigned_by(head, hbody, wkeys)
                except Exception:  # noqa: BLE001
                    head_ok = False
                if not head_ok:
                    problems.append(
                        "witness: this pack says a witness saw a tree beyond the one it contains, "
                        "and carries no cosignature from a pinned key for that tree. The size and "
                        "root being reconciled against are the producer's own claim.")
                    settled = True

            candidates = [x for x in lineage
                          if int(x.get("size", -1)) == want_size and x.get("root") == want_root]
            cosigned = [x for x in candidates if x.get("cosignedNote")]
            for rec in cosigned if head_ok or not wkeys else []:
                try:
                    sealed = parse_seal_note(rec["cosignedNote"])
                    sbody = note_body(sealed["origin"], sealed["size"], sealed["root"], sealed["extra"])
                except Exception as exc:  # noqa: BLE001
                    problems.append(f"witness: the seal offered for this gap is not a readable seal "
                                    f"note ({exc})")
                    settled = True
                    continue
                want_log = (hashlib.sha256(sealed["origin"].encode() + b"\n\x01" + pub).digest()[:4].hex()
                            if pub else "")
                if not pub or not any(nm == sealed["origin"] and kh == want_log
                                      and ed25519_verify(pub, sbody.encode(), sg)
                                      for nm, kh, sg in sealed["signatures"]):
                    problems.append(f"witness: the seal closing size {rec.get('size')} is not signed "
                                    "by this log's key")
                    settled = True
                    continue
                if sealed["size"] != want_size or sealed["root"].hex() != want_root:
                    problems.append("witness: the seal note does not close the tree the witness attested")
                    settled = True
                    continue
                # The archive digest and epoch come from the SIGNED note, never from the JSON beside
                # it. Reading them off the record handed an auditor a digest the producer chose, for
                # the one artefact that holds the entries this pack no longer contains.
                if rec.get("archiveSha256") not in (None, sealed["archiveSha256"]):
                    problems.append("witness: the archive digest recorded beside this seal is not "
                                    "the one the seal note signs")
                    settled = True
                    continue
                if wit.get("epoch") is not None and sealed["epoch"] != int(wit["epoch"]) - 1:
                    problems.append(
                        f"witness: the seal offered closes epoch {sealed['epoch']}, but this pack is "
                        f"in epoch {wit['epoch']}. Only the seal immediately before this epoch can "
                        "explain where its predecessor went.")
                    settled = True
                    continue
                if not wkeys:
                    continue
                by, _ = _cosigned_by(sealed, sbody, wkeys)
                if not by:
                    problems.append(f"witness: the seal closing size {rec.get('size')} is not "
                                    "cosigned by any pinned witness key")
                    settled = True
                    continue
                print(f"witness: the witnessed size ({want_size}) is beyond this tree because the "
                      f"log was SEALED at that exact size and root, closing epoch {sealed['epoch']} "
                      f"— cosigned by {by}, which a rollback cannot obtain: a witness only cosigns "
                      "a seal closing the tree it last attested. The archived entries are in "
                      f"{seal.get('archive') or 'the named archive'}, digest "
                      f"{sealed['archiveSha256'][:16]}…, and are not in this pack.")
                print("      That explains the gap at the epoch boundary and nothing else: it is "
                      "not a statement about the entries here, which are in the epoch after it.")
                settled = True
                break
            if settled:
                pass
            elif cosigned and not wkeys:
                print(f"witness: the witnessed size ({want_size}) is beyond this tree. The pack "
                      "carries a witness-cosigned seal that would explain it, but with no "
                      "UNDERWRIT_WITNESS_KEY pinned a cosignature is a line the producer could "
                      "have written. Pin the witness's key to turn this into a verdict.")
            else:
                # An `audit.seal` entry is an ordinary append that anyone who can write the log can
                # make; nothing in this pack checks its stated size or root against anything. So an
                # unwitnessed seal is the producer's account of why the witnessed tree is gone, and
                # a rollback dressed as a seal looks identical from here.
                print(f"witness: NOT CHECKED — the witnessed size ({want_size}) is beyond this "
                      f"tree. The log says it was sealed at size {seal.get('size')}, and no witness "
                      "has cosigned a seal closing the tree the witness attested, so this pack "
                      "cannot tell a lawful seal from a shortened history. Verify the sealed "
                      f"archive ({seal.get('archive') or 'unnamed'}) against the witness, or pin "
                      "UNDERWRIT_WITNESS_KEY, which refuses this pack outright.")
        elif wit.get("consistency"):
            con = wit["consistency"]
            # The cosigned note is the whole point: without checking it, `oldSize`/`oldRoot` are
            # just numbers the producer chose, and it can name any prefix of its own current tree —
            # including one that omits everything it deleted. A proof to an unattested root proves
            # nothing at all.
            note_ok, note_why = False, "no cosigned note shipped with the proof"
            wnote = wit.get("cosignedNote") or ""
            if wnote:
                try:
                    wcp = parse_note(wnote)
                    if wcp["size"] != int(con["oldSize"]) or wcp["root"].hex() != con["oldRoot"]:
                        note_why = ("the cosigned note is for a different tree than the proof claims "
                                    f"(note: size {wcp['size']}; proof: size {con['oldSize']})")
                    elif wkeys:
                        wbody = note_body(wcp["origin"], wcp["size"], wcp["root"], wcp["extra"])
                        wsigs = [(n, kh, rest) for n, kh, rest in wcp["signatures"] if len(rest) == 72]
                        for wkey in wkeys:
                            wpub = base64.b64decode(wkey)
                            for n, kh, rest in wsigs:
                                want = hashlib.sha256(n.encode() + b"\n\x04" + wpub).digest()[:4].hex()
                                t = int.from_bytes(rest[:8], "big")
                                msg = f"cosignature/v1\ntime {t}\n".encode() + wbody.encode()
                                if kh == want and ed25519_verify(wpub, msg, rest[8:]):
                                    note_ok, note_why = True, ""
                                    break
                            if note_ok:
                                break
                        if not note_ok:
                            note_why = "no pinned witness key verifies the cosignature on that earlier size"
                    else:
                        note_why = "no witness key pinned, so the cosignature on that size is shown, not verified"
                except (ValueError, KeyError, IndexError) as exc:
                    note_why = f"the cosigned note could not be read ({type(exc).__name__})"
            try:
                ok_c = verify_consistency(
                    int(con["oldSize"]), int(con["newSize"]),
                    bytes.fromhex(con["oldRoot"]), bytes.fromhex(con["newRoot"]),
                    [bytes.fromhex(p) for p in con["proof"]])
            except (ValueError, KeyError, TypeError) as exc:
                ok_c = False
                print(f"witness: consistency proof malformed ({type(exc).__name__}: {exc})")
            if not ok_c:
                problems.append(
                    f"witness: this tree is NOT consistent with the one {wit.get('witness') or 'the witness'} "
                    f"cosigned at size {con['oldSize']} — entries present then are not all present now, "
                    "which is what a rewritten or shortened history looks like")
            elif bytes.fromhex(con["newRoot"]) != cp["root"] or int(con["newSize"]) != cp["size"]:
                problems.append("witness: the consistency proof is against a different tree than this "
                                "bundle's checkpoint")
            elif note_ok:
                witness_satisfied = True
                # A pinned key verified a second party's signature over that earlier size, and this
                # tree provably extends it. This is the only statement a bundle can make about
                # completeness, and it only holds with the key pinned.
                print(f"witness: {wit.get('witness') or 'a witness'} cosigned size {con['oldSize']}, "
                      f"verified against a pinned key, and this tree provably extends it — nothing "
                      f"recorded by then has been removed")
            elif "witness" in require:
                problems.append(f"witness: {note_why}, so the consistency proof rests on a size and "
                                "root the producer chose; it shows nothing about completeness")
            else:
                print(f"witness: this tree extends a tree of size {con['oldSize']} that the pack "
                      f"attributes to {wit.get('witness') or 'a witness'} — but {note_why}. Until that "
                      "cosignature is verified against a key you obtained elsewhere, the earlier tree "
                      "is one the producer named, so this says nothing about completeness")
        if "witness" in require and not witness_satisfied:
            problems.append("witness: a witness key is pinned, and nothing in this bundle carries a "
                            "cosignature that key verifies — neither on this checkpoint nor on an "
                            "earlier size this tree provably extends")
        # External clocks. An RFC 3161 token binds SHA-256(checkpoint body) to a time a third party
        # signed; we check the imprint here and hand the CMS signature to OpenSSL when it is present.
        imprint_hex = hashlib.sha256(body).hexdigest()
        tsr = HERE / "timestamps" / "checkpoint.tsr"
        if tsr.exists():
            try:
                info = parse_tsr(tsr.read_bytes())
            except (IndexError, ValueError, TypeError):
                info = {"ok": False}
            if not info.get("ok") or info.get("imprint") != imprint_hex or info.get("hashAlg") not in (None, "sha256"):
                problems.append("timestamp: the RFC 3161 token does not cover this checkpoint's body (imprint or hash algorithm differs)")
            else:
                import shutil, subprocess
                ca = os.environ.get("UNDERWRIT_TSA_CA", "").strip()
                if ca and shutil.which("openssl"):
                    r = subprocess.run(["openssl", "ts", "-verify", "-in", str(tsr), "-digest", imprint_hex,
                                        "-CAfile", ca], capture_output=True, text=True)
                    if r.returncode == 0 and "Verification: OK" in r.stdout:
                        print(f"timestamp: TSA signature and chain verified by openssl; this checkpoint existed at "
                              f"{info['genTime']} (serial {info['serial']})")
                    else:
                        why = ((r.stderr or r.stdout).strip().splitlines() or ["no output"])[-1]
                        problems.append(f"timestamp: openssl could not verify the TSA signature against UNDERWRIT_TSA_CA: {why}")
                elif ca:
                    problems.append("timestamp: UNDERWRIT_TSA_CA is set but openssl is not on PATH, so the TSA signature "
                                    "could not be checked")
                else:
                    print(f"timestamp: RFC 3161 token present, imprint matches; its claimed time {info['genTime']} "
                          f"(serial {info['serial']}) is UNVERIFIED until the TSA signature is checked — set UNDERWRIT_TSA_CA "
                          "to the TSA's CA bundle with openssl on PATH, or run: openssl ts -verify -in "
                          f"timestamps/checkpoint.tsr -digest {imprint_hex} -CAfile <ca.pem>")
                meta = next((t for t in (pack["merkle"].get("timestamps") or [])
                             if t.get("kind") != "ots"), {})
                if meta.get("nonceChecked") is not True:
                    # `is not True`, not `is False`: a bundle that simply does not carry the field —
                    # every bundle issued before the check existed — has not had its freshness
                    # proven either, and reporting only the explicit `False` case quietly gave all
                    # of those a pass.
                    print("timestamp: the freshness of this token was NOT established. Nothing here "
                          "distinguishes it from a response recorded earlier for the same imprint, "
                          "so its time is a claim about when the TSA first saw this tree rather "
                          "than about when this token was obtained. (RFC 3161's nonce is what "
                          "settles that; the issuer either accepted a TSA that does not echo it, "
                          "or predates the check.)")
        ots = HERE / "timestamps" / "checkpoint.ots"
        if ots.exists():
            meta = next((t for t in (pack["merkle"].get("timestamps") or []) if t.get("kind") == "ots"), {})
            print(f"timestamp: OpenTimestamps proof present ({meta.get('status', 'unknown')}, calendar "
                  f"{meta.get('calendar', '?')}) — upgrade and verify with the ots client; a pending proof is not an anchor")
        if not tsr.exists() and not ots.exists():
            print("timestamp: no external clock — the checkpoint's time rests on the log and its witnesses")
        for entry in entries:
            proof = entry.get("inclusionProof")
            idx = entry.get("leafIndex")
            if proof is None or idx is None:
                continue
            leaf = leaf_hash(entry["hash"].encode("ascii"))
            try:
                got = root_from_inclusion(idx, cp["size"], leaf, [bytes.fromhex(p) for p in proof])
            except ValueError as exc:
                problems.append(f"audit entry seq {entry['seq']}: inclusion proof malformed ({exc})")
                continue
            if got != cp["root"]:
                problems.append(f"audit entry seq {entry['seq']}: inclusion proof does not reach the checkpoint root")
            else:
                proven += 1
        print(f"merkle: {proven} of {len(entries)} entries proven at their positions under checkpoint size {cp['size']}")

        # Session heads (format 4): the session's last entry at each committed size is in this
        # pack, or the session had none then. This is what catches the final entries cut off.
        heads_sec = pack["merkle"].get("scopeHeads") or {}
        if not isinstance(heads_sec, dict):
            heads_sec = {}
        wit_note = None
        if wit.get("consistency") and wit.get("cosignedNote"):
            try:
                wit_note = parse_note(str(wit["cosignedNote"]))
            except (ValueError, IndexError, TypeError):
                wit_note = None
        for label, nparsed, strong in (("checkpoint", cp, witness_satisfied and not wit.get("consistency")),
                                       ("witnessed", wit_note, witness_satisfied)):
            if nparsed is None:
                continue
            try:
                line = parse_scopes_line(nparsed["extra"])
            except ValueError as exc:
                problems.append(f"session heads: the {label} note's extension line is malformed ({exc})")
                continue
            if line is None:
                if label == "checkpoint" and session_entries:
                    print("session heads: this checkpoint commits to no session heads (issued before "
                          "format 4, or with UNDERWRIT_SCOPE_HEADS=off) — the session's final entries "
                          "could be removed without this pack showing it")
                continue
            if not subject_id:
                continue
            sec = heads_sec.get(label)
            if not isinstance(sec, dict) or sec.get("error") or not isinstance(sec.get("proofs"), list):
                why = (sec or {}).get("error") if isinstance(sec, dict) else None
                problems.append(f"session heads: the {label} note commits to every session's last entry, "
                                f"and this pack carries no proof for {subject_id}"
                                + (f" ({why})" if why else "") +
                                " — so it cannot show that the session's last entries are present")
                continue
            size_n = int(nparsed["size"])
            mine = next((x for x in sec["proofs"] if isinstance(x, dict) and x.get("scope") == subject_id), None)
            if mine is None:
                problems.append(f"session heads: no {label} proof for {subject_id}")
                continue

            def at(leaf):
                return root_from_inclusion(int(leaf["index"]), int(line["count"]),
                                           scope_leaf(leaf["scope"], leaf["seq"], leaf["hash"]),
                                           [bytes.fromhex(p) for p in leaf["proof"]]) == line["root"]
            try:
                if mine.get("present"):
                    if not at(mine):
                        problems.append(f"session heads: the {label} proof for {subject_id} does not reach "
                                        "the root the note signed")
                        continue
                    hit = [e for e in session_entries if e.get("seq") == mine["seq"]]
                    if not hit or hit[0].get("hash") != mine["hash"]:
                        problems.append(
                            f"session heads: at size {size_n} the log committed that {subject_id}'s last "
                            f"entry was seq {mine['seq']}, and this pack does not contain it. The "
                            "session's final entries have been removed")
                        continue
                    later = [e for e in session_entries if isinstance(e.get("leafIndex"), int)
                             and e["leafIndex"] < size_n and e.get("seq") > mine["seq"]]
                    if later:
                        problems.append(f"session heads: this pack shows entries of {subject_id} before size "
                                        f"{size_n} after the head committed at that size")
                        continue
                    after = sum(1 for e in session_entries if e.get("seq", 0) > mine["seq"])
                    who = ("a witness cosigned, verified against a pinned key" if strong
                           else "the log signed" + ("" if label == "checkpoint" else " and a witness is said to have cosigned"))
                    print(f"session heads: {subject_id}'s last entry at size {size_n} (seq {mine['seq']}) is "
                          f"present — a commitment {who}"
                          + (f"; {after} later entr{'y' if after == 1 else 'ies'} rest on the log key alone" if after else ""))
                else:
                    lft, rgt = mine.get("left"), mine.get("right")
                    k = subject_id.encode("utf-8")
                    ok_abs = ((lft is None or (at(lft) and lft["scope"].encode("utf-8") < k)) and
                              (rgt is None or (at(rgt) and rgt["scope"].encode("utf-8") > k)) and
                              ((lft is None and rgt is not None and int(rgt["index"]) == 0) or
                               (rgt is None and lft is not None and int(lft["index"]) == int(line["count"]) - 1) or
                               (lft is not None and rgt is not None and int(rgt["index"]) == int(lft["index"]) + 1) or
                               (lft is None and rgt is None and int(line["count"]) == 0)))
                    if not ok_abs:
                        problems.append(f"session heads: the {label} proof that {subject_id} had no entries "
                                        f"at size {size_n} does not hold")
                        continue
                    early = [e for e in session_entries if isinstance(e.get("leafIndex"), int) and e["leafIndex"] < size_n]
                    if early:
                        problems.append(f"session heads: the log committed at size {size_n} that {subject_id} "
                                        "had no entries, and this pack shows some before that size")
                        continue
                    print(f"session heads: {subject_id} had no entries at size {size_n}, proven against the "
                          f"{label} note's commitment")
            except (KeyError, TypeError, ValueError) as exc:
                problems.append(f"session heads: the {label} proof is malformed ({type(exc).__name__})")
    elif manifest.get("format", 1) >= 2:
        print("merkle: no checkpoint in this bundle — positions not proven, chain hashes only")

    # The build statement (spec §12): what produced this pack, as the producer states it. Reported,
    # never a failure unless --require release asks for a signed release build.
    build = pack.get("build")
    if isinstance(build, dict):
        for line, bad in build_lines(build):
            print(("build: WARNING — " if bad else "build: ") + line)
        b = build.get("build") if isinstance(build.get("build"), dict) else {}
        if "release" in require and b.get("status") != "signed":
            problems.append(f"build: a {b.get('status') or 'unknown'} build, not a signed Underwrit release, "
                            "and --require release asks for one")
    elif "release" in require:
        problems.append("build: this pack carries no build statement, and --require release asks for one")
    elif manifest.get("format", 1) >= 2:
        print("build: no build statement in this pack (made by a version before they were added)")

    key = os.environ.get("EVIDENCE_SIGNING_KEY", "").strip()
    signature = manifest.get("signature")
    if signature and key:
        expected = hmac.new(key.encode("utf-8"), canonical(manifest["files"]), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            problems.append("signature does not match: this bundle was not produced with that key")
        else:
            print("signature: verified")
    elif signature:
        print("signature: present, not checked (set EVIDENCE_SIGNING_KEY to check it)")
    elif not ed:
        print("signature: none (this bundle proves it is internally consistent, not who made it)")

    if not entries:
        print("NOTE: this pack contains no audit entries. There is nothing here to verify —")
        print("      that is not the same as a clean result.")

    if problems:
        print(f"\nFAILED — {len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1
    print(f"\nOK — {len(manifest['files'])} file(s) intact, {len(entries)} audit entr(ies) verified.")
    print(f"      signatures checked with: {ED25519_BACKEND}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 — a verifier that crashes has said nothing
        print(f"\nFAILED — verifier error: {type(exc).__name__}: {exc}")
        raise SystemExit(1)
