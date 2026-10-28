"""Check an Underwrit agent passport. Standard library plus `ed25519.py`; runs anywhere.

SPDX-License-Identifier: MIT — Copyright (c) 2026 CAID LLC (Underwrit). This module is MIT, unlike the
rest of the package (proprietary, see LICENSE), so any company receiving an agent's request can
check its passport without Underwrit. Exported to the public verifier (scripts/export_verifier.py).

    python3 passport_verify.py <passport.jwt> --key <issuer's base64 Ed25519 key> [--revocations <url or file>]

A passport is a compact JWS (EdDSA, `typ` underwrit-passport+jwt) over:

    {"agentId", "owner", "authorityRoot", "policyPacks", "policyDigest", "stats", "issuedBy", "iat", "exp", "jti"}

It is good when the signature verifies under the issuer's published log key (the key their
`GET /v1/keys` serves, pinned by you, never taken from the passport), it has not expired, and its
`jti` is not on the issuer's signed revocation list.
"""

from __future__ import annotations

import base64
import json
import sys
import time
import urllib.request

try:
    from . import ed25519
except ImportError:  # run as a script beside ed25519.py
    import ed25519  # type: ignore

TYP = "underwrit-passport+jwt"


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jws(token: str, public: bytes) -> dict:
    h, p, s = token.strip().split(".")
    header = json.loads(_unb64u(h))
    if header.get("alg") != "EdDSA":
        raise ValueError("not an EdDSA token")
    if not ed25519.verify(public, f"{h}.{p}".encode(), _unb64u(s)):
        raise ValueError("the signature does not verify under the issuer's key")
    return {"header": header, "payload": json.loads(_unb64u(p))}


def check(token: str, public_key_b64: str, *, revoked: set | None = None, now: float | None = None) -> dict:
    """{"ok": bool, "problems": [...], "passport": {...}}"""
    problems: list[str] = []
    try:
        got = _jws(token, base64.b64decode(public_key_b64))
    except (ValueError, TypeError) as exc:
        return {"ok": False, "problems": [str(exc)], "passport": None}
    p = got["payload"]
    if got["header"].get("typ") != TYP:
        problems.append("not an Underwrit agent passport")
    if (now or time.time()) > float(p.get("exp") or 0):
        problems.append("expired")
    if revoked is not None and p.get("jti") in revoked:
        problems.append("revoked by the issuer")
    return {"ok": not problems, "problems": problems, "passport": p}


def revocations(source: str, public_key_b64: str) -> set:
    """The issuer's signed revocation list (`GET /v1/passports/revocations`)."""
    if source.startswith(("https://", "http://")):
        with urllib.request.urlopen(source, timeout=10) as r:
            token = r.read().decode()
    else:
        with open(source) as f:
            token = f.read()
    return set(_jws(token.strip().strip('"'), base64.b64decode(public_key_b64))["payload"].get("revoked") or [])


def main(argv: list[str]) -> int:
    if len(argv) < 3 or "--key" not in argv:
        print(__doc__.strip().splitlines()[5].strip(), file=sys.stderr)
        return 2
    token = open(argv[0]).read() if not argv[0].count(".") == 2 else argv[0]
    key = argv[argv.index("--key") + 1]
    rev = revocations(argv[argv.index("--revocations") + 1], key) if "--revocations" in argv else None
    out = check(token, key, revoked=rev)
    print(json.dumps(out, indent=2))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
