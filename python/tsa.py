"""Time-stamping: an external clock for a checkpoint. RFC 3161 first, OpenTimestamps second.

SPDX-License-Identifier: MIT — Copyright (c) 2026 Underwrit. MIT, unlike the rest of the
package (proprietary, see LICENSE): the response-reading half of this module (`SHA256_OID` through `parse_response`) is
embedded in every bundle's `verify.py`, which must be copyable anywhere. See NOTICE.


A log's own timestamps prove nothing — the log wrote them. What a bundle needs is a party
independent of both the operator and Underwrit asserting "this hash existed before T". Two kinds:

- **RFC 3161** time-stamp tokens from a TSA (many free; eIDAS-qualified ones for EU buyers). The
  request is a small DER structure carrying only the SHA-256 of the checkpoint body — the TSA
  never sees a byte of content ("the TSA MUST NOT examine the imprint", §2.1). The response is a
  CMS SignedData. This module encodes the request and decodes enough of the response to extract
  the TSTInfo's `genTime`, `messageImprint` and `serialNumber` and to check the imprint matches;
  full verification of the TSA's signature and certificate chain is left to OpenSSL
  (`openssl ts -verify`), which `verify.py` invokes when it is present and says so when it is not.

- **OpenTimestamps** anchors into Bitcoin through public calendars. The calendar answers a
  submission with a *pending* attestation that becomes a Bitcoin attestation hours later; a
  pending proof is stored and labelled pending, never presented as an anchor.

Both are optional (`UNDERWRIT_TSA_URL`, `UNDERWRIT_OTS_CALENDARS`); a plane without either still signs and
witnesses, and the bundle says which clocks it has.
"""

from __future__ import annotations

import base64
import os
import time
import urllib.error
import urllib.request

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


def parse_response(resp: bytes) -> dict:
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


def fetch_token(url: str, digest: bytes, timeout: float = 10.0) -> tuple[bytes, int]:
    """The token, and the nonce that was sent — which is the only thing the caller can check it by."""
    tok, nonce, _ = _fetch(url, digest, timeout=timeout)
    return tok, nonce


def _fetch(url: str, digest: bytes, *, timeout: float = 10.0, headers: dict | None = None) -> tuple[bytes, int, str]:
    nonce = int.from_bytes(os.urandom(8), "big")
    req = urllib.request.Request(url, data=timestamp_request(digest, nonce=nonce), method="POST",
                                 headers={"Content-Type": "application/timestamp-query", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), nonce, r.headers.get("X-Underwrit-TSA", "")


_proxy_absent_until = 0.0


def _source() -> tuple[str, dict, bool]:
    """(url, headers, via_proxy). `UNDERWRIT_TSA_URL` when set; otherwise the control plane's proxy,
    when there is a control plane and `UNDERWRIT_TSA` is not `off` — so a node with a hosted control
    plane is time-stamped with no configuration of its own. The proxy forwards the request byte for
    byte and the authority signs the token, so going through it changes who can delay a stamp, not
    who can forge one: the nonce and imprint below are checked the same either way."""
    url = os.environ.get("UNDERWRIT_TSA_URL", "").strip()
    if url:
        return url, {}, False
    if os.environ.get("UNDERWRIT_TSA", "").strip().lower() in ("off", "0", "false", "no"):
        return "", {}, False
    from .node import control_url, node_token

    base = control_url()
    if not base or time.time() < _proxy_absent_until:
        return "", {}, False
    from . import integrity
    from .node import NODE_ID

    tok = node_token()
    # The node name and build line go to the control plane only, never to a third-party authority.
    return f"{base}/v1/timestamp", {"X-Underwrit-Build": integrity.header(), "X-Underwrit-Node": NODE_ID,
                                    **({"Authorization": f"Bearer {tok}"} if tok else {})}, True


_REPORTED: dict[str, float] = {}


def _report(message: str, *, kind: str, url: str) -> None:
    """Say it once an hour, and say it somewhere alertable.

    A checkpoint every sixty seconds against a non-compliant TSA was five lines of `print` to
    stdout every minute, forever, and only to stdout — so the thing an operator needs to act on was
    both unmissable in the logs and impossible to alert on.
    """
    now = time.time()
    if now - _REPORTED.get(kind + url, 0.0) > 3600:
        _REPORTED[kind + url] = now
        print(message, flush=True)
    try:
        from . import obs
        obs.log(f"tsa.{kind}", tsa=url)
    except Exception:  # noqa: BLE001
        pass


def _allow_missing_nonce() -> bool:
    return os.environ.get("UNDERWRIT_TSA_ALLOW_NO_NONCE", "").strip().lower() in ("1", "true", "yes")


def stamp(digest: bytes) -> dict | None:
    """A time-stamp token for `digest` from UNDERWRIT_TSA_URL, or None when none is
    configured, unreachable, or answers something this request did not ask for.

    The nonce is checked. It was generated and sent and then discarded, which left the one
    freshness property the protocol offers unused: without it, a token recorded from any earlier
    exchange with the same TSA over the same imprint is indistinguishable from a fresh one, and an
    operator replaying a stored response could attach a time of their choosing to a tree that did
    not exist then. RFC 3161 §2.4.2 makes echoing it a MUST, so a response without one is refused
    unless `UNDERWRIT_TSA_ALLOW_NO_NONCE=1` names the TSA's non-compliance deliberately — and the
    record then says so, because a bundle should carry what was and was not checked.
    """
    global _proxy_absent_until
    url, headers, via_proxy = _source()
    if not url:
        return None
    try:
        tok, nonce, upstream = _fetch(url, digest, headers=headers)
    except urllib.error.HTTPError as exc:
        if via_proxy and exc.code in (401, 403, 404, 501):
            # An open control plane, or one with no authority configured: ask again in an hour
            # rather than on every checkpoint.
            _proxy_absent_until = time.time() + 3600
        return None
    except (urllib.error.URLError, OSError, ValueError):
        return None
    proxy = url if via_proxy else ""
    if via_proxy:
        url = upstream or url
    try:
        info = parse_response(tok)
    except (ValueError, IndexError):
        return None
    if not info["ok"] or info["imprint"] != digest.hex() or info.get("hashAlg") != "sha256":
        return None
    got = info.get("nonce")
    if got is None:
        if not _allow_missing_nonce():
            _report(f"underwrit: the TSA at {url} returned a token with no nonce, which RFC 3161 "
                  "§2.4.2 requires when the request carries one. Without it a recorded response "
                  "cannot be told from a fresh one, so the token is discarded. Set "
                  "UNDERWRIT_TSA_ALLOW_NO_NONCE=1 to accept this TSA anyway; the bundle will say "
                    "the freshness of its timestamps was not checked.", kind="no_nonce", url=url)
            return None
        info["nonceChecked"] = False
    elif got != nonce:
        _report(f"underwrit: the TSA at {url} echoed nonce {got:x}, not the {nonce:x} this request "
                "sent. The token answers a different request and has been discarded.",
                kind="wrong_nonce", url=url)
        return None
    else:
        info["nonceChecked"] = True
    # The value itself is not kept: it proves freshness to the party that sent it and nothing to a
    # later reader, and putting a 64-bit random in the bundle only invites it to be compared.
    info.pop("nonce", None)
    return {"tsa": url, **({"via": proxy} if proxy else {}), "token": base64.b64encode(tok).decode(), **info,
            "fetchedAt": time.time()}


# --------------------------------------------------------------------------------------------
# OpenTimestamps: submit, keep the pending proof.


def ots_submit(digest: bytes, timeout: float = 10.0) -> dict | None:
    cals = [c.strip() for c in os.environ.get("UNDERWRIT_OTS_CALENDARS", "").split(",") if c.strip()]
    for cal in cals:
        try:
            req = urllib.request.Request(f"{cal.rstrip('/')}/digest", data=digest,
                                         headers={"Content-Type": "application/x-www-form-urlencoded",
                                                  "Accept": "application/vnd.opentimestamps.v1"}, method="POST")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return {"calendar": cal, "proof": base64.b64encode(r.read()).decode(), "status": "pending",
                        "submittedAt": time.time(),
                        "note": "Pending: the calendar has queued this digest for a Bitcoin attestation; upgrade "
                                "with the ots client in a few hours. A pending proof is not an anchor."}
        except (urllib.error.URLError, OSError, ValueError):
            continue
    return None
