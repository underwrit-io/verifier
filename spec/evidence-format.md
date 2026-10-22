# Underwrit evidence format

**Versions 1, 2, 3 and 4.** A record of what a system did, and a bundle anybody can check without the
system that produced it.

This document is the whole specification. It is short on purpose: a format is only open if
implementing it is cheap, and the reference implementation in `underwrit/recorder.py` is under a hundred and fifty
lines of standard-library Python. If either is hard to follow, the format is wrong and should change.

---

## 1. What this proves, and what it does not

Be precise about this before anything else, because a verifier that overstates itself is worse than
no verifier — it converts an unchecked record into a confident one.

**It proves** that no entry present in a bundle has been altered or reordered since it was written,
and that no file in the bundle has been edited since it was assembled.

**It does not prove** that the record is complete. Nothing inside a bundle can show an entry was
removed: the neighbours that would reveal the gap are, by construction, the ones that are missing. A
conformant verifier must say so rather than implying otherwise.

**It does not prove origin** unless the bundle is signed. An unsigned bundle demonstrates internal
consistency only — anybody can produce a self-consistent chain. Signing is §5.

---

## 2. The entry

An entry has exactly these ten payload fields. An implementation with a different set is not
conformant, because the set determines the hash.

| field | type | meaning |
|---|---|---|
| `at` | number | Seconds since the Unix epoch, as a float |
| `actor` | string | Who or what acted — a person, a service, an agent |
| `actor_id` | string | A stable identifier for the actor, if there is one |
| `action` | string | What was attempted, e.g. `tool.call`, `terraform.apply` |
| `environment` | string | Where, e.g. `production` |
| `target` | string | What was acted on. This is the primary correlation key |
| `outcome` | string | The result — see §2.1 |
| `reason` | string | Why, in words, especially for a refusal |
| `detail` | object | Anything else. Hashed as an **object**, never as a string of JSON |
| `source_ip` | string | Origin of the request, where meaningful |

Every string field is a string. **Coerce before hashing, not after.** The hash is computed over the
values going in and re-computed over the values coming back out, so any coercion a store performs
between those two moments breaks the entry permanently — and an entry that cannot verify is
indistinguishable from one somebody edited. A `TEXT` column receiving an integer is the ordinary way
this happens.

`detail` is hashed as an object. Serialising it to a string first produces a different payload and
every entry then fails.

### 2.1 Outcome

`outcome` is free text, but a conformant record **must** distinguish refusals from successes. A log
containing only what worked cannot show somebody probing for what does not, which is most of what an
audit log is for. The reference implementation uses `allowed`, `denied`, `succeeded`, `failed` and
`require_human` (the §6 test vectors predate that spelling and keep `requires_human`; the hashes are over whatever word was recorded).

### 2.2 The scope of a decision, and a held scope

Informative: these are `detail` fields and `action` names the reference data plane writes. They
change no hash rule; a verifier that does not know them verifies the entries exactly as before.

A `decision` entry over a sink carries `detail.scope`: `<tool family>:<keyed digest>` of the
target-identifying argument values, or `explicit:<keyed digest>` when the runtime named the target
itself. It names *which* target was reached without saying what it was — the digest is an HMAC
under a key held only by the producing plane, so two entries with the same scope reached the same
target and nothing in the pack says which. When the runtime pinned the tool's definition, the entry
also carries `detail.toolDefinitionDigest` (SHA-256 hex, §2.3), and so do the `decision.approval`
and `decision.resolve` entries for the same decision.

| action | written when | `detail` |
|---|---|---|
| `scope.hold` | an outcome is reported `uncertain`, or a claimed decision reports nothing within the operator's deadline | `holdId`, `scope`, `decisionId`, `sessionId`, `placedBecause` (`uncertain` / `deadline`) |
| `scope.hold.release` | an approver answers a release; one entry per answer, including the first of two | `holdId`, `scope`, `decisionId`, `approver`, `identifiedVia`, `countsTowardQuorum`, `quorumNeeded`, `quorumHave` |
| `scope.hold.clear` | the hold clears — exactly once per hold | `holdId`, `scope`, `decisionId`, `clearedHow` (`reconcile` / `probe` / `person`); for `probe`: `probeStatus`, `probeDigest`, `probeChars`, `probedBy` — never the read-back text; for `person`: `subject`, `identifiedVia`, `releasedBy`, `answers`, `quorumNeeded` |

While a hold stands, a `decision` entry on the same scope carries `detail.scopeHold`
`{"id", "decisionId"}` and its `reason` begins `hold.unknown_outcome: <decision id>`; a
`decision.claim` entry refused for it carries `scopeHold` and `refusedBecause: "scope_held"`. A
pack whose `scope.hold` has no matching `scope.hold.clear` describes a target whose outcome is
still unknown, and a reader should treat every later action on that scope accordingly.

### 2.3 The tool-definition digest

`toolDefinitionDigest` is `SHA-256(JSON({"description", "inputSchema", "name"}))` over the tool's
definition, with the three keys and no others, keys sorted, separators `,` and `:` with no
whitespace, non-ASCII characters left as UTF-8 (`ensure_ascii=False`), a missing `description` as
`""` and a missing `inputSchema` as `{}`. A `decision.claim` entry says `toolDefinitionBound: true`
or `false`; when `false`, the approval was never bound to a definition and nothing was checked
against one. A refused claim says why in `refusedBecause`: `tool_definition_changed` (and carries
both digests) or `tool_definition_not_presented`.

---

## 3. The chain

Each entry carries `prev_hash` and `hash`.

```
GENESIS  = "0" * 64
body     = json.dumps(payload, sort_keys=True, separators=(",", ":"))
hash     = sha256(prev_hash + body).hexdigest()
```

`sort_keys` and the pinned separators are both required. The same entry must hash identically on
every machine, every language and every library version; default JSON spacing has changed between
releases of common libraries, and an implementation relying on it will disagree with this one.

The first entry's `prev_hash` is `GENESIS`. Sixty-four zeros rather than an empty string, so the hash
input has the same shape for every entry.

### 3.0 How numbers are written

**Normative, and the one rule that is invisible until you implement this in a second language.**

`at` is a floating-point number. Every other number in a payload is an integer. They are written
differently, and getting it wrong changes the hash:

- **An integer** is its shortest decimal form: `0`, `12`, `-3`.
- **A float** is written as CPython's `repr()` writes it — which is what `json.dumps` emits, and
  what every hash in this format was computed over. Concretely: the shortest decimal string that
  round-trips to the same double; a trailing `.0` when the value is integral; exponent form when
  the magnitude is `>= 1e16` or `< 1e-4`, with the exponent signed and at least two digits, and the
  mantissa written without a forced `.0`.

```
1757600000.0   ->  1757600000.0        NOT 1757600000
1.0            ->  1.0                 NOT 1
1e16           ->  1e+16               NOT 1.0e+16 or 10000000000000000
1e-7           ->  1e-07               NOT 1e-7
1789106754.158 ->  1789106754.158
```

`JSON.stringify` in JavaScript, and the default encoder in most languages, writes `1757600000` for
the first of those. A timestamp that lands on a whole second — a seal, a coarse clock, a test
vector — therefore hashes differently outside Python unless an implementation applies this rule.
`site/verify.js` in this repository is a conforming second implementation, and
`tests/test_second_implementation.py` holds the two to each other.

Non-finite floats (`NaN`, `Infinity`) are not representable: a producer MUST NOT put one in a
payload, and a verifier meeting one MUST fail rather than guess an encoding for it.

### 3.1 Verifying a subset

A bundle usually carries a *subset* of a shared log — one subject's entries, interleaved with every
other actor's. **Verify each entry against its own recorded `prev_hash`. Never walk from GENESIS.**

A genesis walk requires each entry to follow the last, which is true of a whole chain and false of
every honest subset; used on a subset it reports "broken" every time, which teaches readers that the
verdict means nothing.

### 3.2 Gaps

Sequence numbers in a bundle will have gaps. That is expected and is not evidence of tampering: the
missing numbers are other actors' entries in the same log. A conformant bundle reports gaps and says
what they mean.

---

## 4. The bundle

A directory. Version 1: four files, no subdirectories. Version 2 (§9) adds `checkpoint` and, when external clocks are configured, `timestamps/checkpoint.tsr` and `timestamps/checkpoint.ots`.

| file | |
|---|---|
| `evidence.json` | The pack — §4.1 |
| `manifest.json` | SHA-256 of every other file, and optionally a signature — §5 |
| `verify.py` | A standalone verifier, standard library only |
| `README.md` | What this is and how to check it, in prose |

`manifest.json` digests every file **except itself**. A manifest cannot contain its own digest, and
an implementation that appears to manage it has made the verifier always pass.

### 4.1 `evidence.json`

```jsonc
{
  "format": 1,
  "generatedAt": 1757404800.0,
  "subject": { "id": "s-1001", "kind": "session", ... },  // host-supplied, open
  "auditEntries": [ ... ],                                 // §2, camelCase keys — §4.2
  "auditChain": {
    "segment":   { "status": "verified" | "broken" | "no-entries", "ok": true|false|null, ... },
    "wholeLog":  { ... },        // the source log's own verdict, if available
    "segmentEntries": 5,
    "note": "..."                // what this cannot prove — §1
  },
  "chainContinuity": { "consecutive": true, "gaps": [ ... ], "note": "..." }
}
```

Additional top-level keys are permitted and carried through unchanged — a host may attach approvals,
policy findings, cost, anything. A host key **must not** shadow a structural key; an implementation
must ignore one that tries, or a producer could replace the verification with its own claim about it.

**`no-entries` is its own status.** A subject with no entries has nothing to verify, which is not a
pass and not a broken chain. `ok` is `null`, never `true`.

### 4.2 Key casing

`evidence.json` presents entries in camelCase — `actorId`, `sourceIp`, `prevHash`. The **hash is
computed over the snake_case field names in §2**. A verifier must map back before hashing. This is an
awkward seam and it is documented rather than fixed because changing it would invalidate every
existing bundle.

---

## 5. Signing

Optional. When `EVIDENCE_SIGNING_KEY` is set, the manifest carries:

```
signature = HMAC-SHA256(key, json.dumps(manifest["files"], sort_keys=True, separators=(",", ":")))
```

A verifier given the key checks it and says `verified`. Given no key it says the signature is present
but unchecked. With no signature at all it must say the bundle proves internal consistency but not
origin — plainly, not in a footnote.

HMAC means the verifier needs the same secret, so it proves origin to somebody who already shares the
key. Public verification needs asymmetric signing and is not in version 1.

---

## 6. Test vectors

An implementation that reproduces these is hashing correctly.

**Entry one**, `prev_hash = GENESIS`:

```
{"action":"tool.call","actor":"agent:mailbot","actor_id":"7","at":1757404800.0,"detail":{"tool":"send_email"},"environment":"production","outcome":"requires_human","reason":"session consumed untrusted content","source_ip":"","target":"s-1001"}
```
```
hash = dbd43c76c519a369620c560eff01adc67599d8549b06f04d96bad0a2e4ae1edd
```

**Entry two**, `prev_hash` = the hash above:

```
{"action":"tool.call","actor":"agent:mailbot","actor_id":"7","at":1757404801.0,"detail":{},"environment":"production","outcome":"allowed","reason":"","source_ip":"","target":"s-1001"}
```
```
hash = 4be1c1026e22a2fbbc130fc52dca1e004869b087cdd71d45dd483a70dec8792b
```

These are asserted by `tests/test_conformance.py`, so the specification and the implementation cannot
drift apart without a test failing.

---

## 7. Versioning

`format` is an integer. Version 1 is §1–§6 of this document; version 2 is §9; version 3 is §10; version 4 is §11.
Each contains a valid pack of the version below it: every entry still verifies by its chain hash
alone, and a version-3 bundle is a version-2 bundle with two additional, *optional* structures.

A change that alters any hash for the same logical entry is a new version, never an amendment —
existing bundles must keep verifying under the version they declare. A verifier meeting a version it
does not know must refuse rather than guess: reading a bundle under the wrong rules produces verdicts
nobody can account for.

---

## 8. Licence

This document, `verify.py`, `site/verify.js` and the verification modules they are built from
(`ed25519.py`, `merkle.py`, `tsa.py`) are **MIT**. Use them, implement them, ship them in a competing
product, embed them in a GPLv2 tool. A format only its author can read is not evidence — the whole
value is being able to hand a bundle to somebody who has no reason to trust you.

The Underwrit *product* is proprietary (the Underwrit Software Licence). None of that reaches the
list above, which is also published on its own as the public Underwrit verifier.


---

## 9. Version 2: a tree, a checkpoint, and a signature anyone can check

Version 1 proves that no entry present has been altered. It cannot prove that an entry sits where
the log says it does, and its HMAC proves origin only to a party who shares the secret — who could
therefore have forged it. Version 2 adds three things. The hashing of entries (§2–§3) is unchanged.

### 9.1 The tree

A Merkle tree per RFC 6962 / RFC 9162 over the live log, one leaf per entry in sequence order:

```
leaf_i  = SHA-256(0x00 ‖ ascii(hash_i))        hash_i is the entry's chain hash, as hex text
node    = SHA-256(0x01 ‖ left ‖ right)
root    = MTH per RFC 9162 §2.1.1 (split at the largest power of two below n)
```

The domain-separation bytes are required. The tree commits to exactly what the chain commits to,
so the two verify each other. An implementation reproducing the RFC 9162 §2.1.5 vectors is hashing
the tree correctly.

### 9.2 The checkpoint

A C2SP signed note (https://c2sp.org/tlog-checkpoint), shipped as the file `checkpoint`:

```
underwrit/<node>
<tree size, ASCII decimal>
<root, base64>

— underwrit/<node> <base64(key hash[4] ‖ Ed25519 signature)>
```

The signature is Ed25519 (RFC 8032) over the three-line body. The key hash is the first four bytes
of `SHA-256(origin ‖ 0x0A ‖ 0x01 ‖ public key)`. A log **must not** sign a checkpoint inconsistent
with one it signed before; a verifier that holds two checkpoints from the same log checks the
consistency proof between them (RFC 9162 §2.1.4) and treats a failure as a rewritten history.

### 9.3 Inclusion proofs

Each entry in `evidence.json` carries `leafIndex` and `inclusionProof` (a list of hex node hashes,
the RFC 9162 §2.1.3.1 audit path). A verifier recomputes the root from the entry's leaf, its index
and its proof, and compares it to the checkpoint's root. Every proof node is consumed and the path
length is checked against the tree shape; a verifier that accepts a shortcut is a verifier that can
be fooled (immudb CVE-2022-36111). An entry sealed into the archive before the tree carries `null`
for both fields and is verified by chain hash only; the pack's `merkle.unplaced` counts them.

### 9.4 The manifest signature

`manifest.json` gains `signatures`, a list of `{alg, keyId, origin, publicKey, signature}`. The
signature is Ed25519 over the canonical JSON (§3) of `manifest["files"]`. The version-1 HMAC
`signature` may coexist for verifiers that share the secret.

### 9.5 What version 2 proves, and what it still does not

- **Proves**: each present entry is unaltered (v1), sits at its stated position in a tree of the
  stated size (proof), and that tree and this bundle were signed by the holder of the log key
  (checkpoint and manifest signatures).
- **Does not prove completeness of a subset.** Nothing inside a bundle can show what was left out.
  Completeness is established by a *witness* — a party that received the same checkpoint from the
  log and can be asked whether it agrees — and by consistency proofs between checkpoints over time.
  That protocol is specified in §9.6; the data structures here are the ones it uses.
- **Does not prove origin from the bundle alone.** The public key inside the bundle shows the bundle
  agrees with itself. Origin is established by obtaining the key out of band (the data plane serves
  it at `GET /v1/keys`) and pinning it when verifying. A conformant verifier says which of the two it
  did.

### 9.6 Witness cosignatures

A witness is a party that receives checkpoints from the log, verifies each one is consistent with
the last it accepted (RFC 9162 §2.1.4), and cosigns it (https://c2sp.org/tlog-cosignature). The
cosignature is an Ed25519 signature over `cosignature/v1\ntime <unix seconds>\n` followed by the
checkpoint body, carried as a further signed-note line whose blob is `key hash[4] ‖ time (8 bytes,
big-endian) ‖ signature`. The witness key hash uses the cosignature algorithm byte:
`SHA-256(witness name ‖ 0x0A ‖ 0x04 ‖ public key)[:4]`, distinct from the `0x01` of an Ed25519 log
line, so a verifier can tell the two kinds of line apart by hash alone. A bundle carrying a cosigned checkpoint shows that a second party saw
this history at that time; a log that later rewrote an entry the witness covers cannot produce a
consistency proof to its next checkpoint and is refused. The witness sees sizes and roots only.

A checkpoint MAY carry more than one cosignature line, one per witness; each is verified
independently against its own key and origin, and verifiers ignore lines from names they do not
know. A bundle cosigned by N witnesses run by different parties is N independent statements that
this history is the one they saw.

### 9.7 External timestamps

A bundle MAY carry `timestamps/checkpoint.tsr`, an RFC 3161 `TimeStampResp` whose `messageImprint`
is SHA-256 over the checkpoint body (`<origin>\n<size>\n<base64 root>\n`), and
`timestamps/checkpoint.ots`, an OpenTimestamps proof over the same digest. `evidence.json` lists
them under `merkle.timestamps` with `kind`, and for RFC 3161 the TSA URL, `genTime`, serial and
imprint; for OpenTimestamps the calendar and a `status` that is `pending` until upgraded. A verifier
MUST check the imprint equals the body's digest; it SHOULD verify the TSA signature and chain against
a trust anchor supplied out of band (`UNDERWRIT_TSA_CA`) and MUST say so when it did not. A pending
OpenTimestamps proof is not evidence of time and MUST NOT be presented as such. Both files are
listed in `manifest.json` and so are covered by the manifest signature.

### 9.8 Test vectors

The tree: RFC 9162 §2.1.5 (roots for 0–8 leaves over the inputs given there). The signature:
RFC 8032 §7.1 test 1. `tests/test_evidence_v2.py` asserts both against this implementation, and
runs the shipped verifier against a bundle before and after tampering with an entry, a leaf index
and the checkpoint.

---

## 10. Version 3: erasure that is still evidence, and a proof the log only grew

Version 2 proves that every entry present is unaltered and sits where it claims in a tree the
producer signed. Two things it cannot express, both of which a real deployment needs:

- **A lawful erasure.** A right-to-erasure request removes an entry's identifying content. Under
  version 2 such an entry cannot be hashed, so a verifier either reports it as tampering — accusing
  an operator of forging their own log for doing what the law required — or skips the check, which
  makes "redacted" a way to show arbitrary content and avoid verification.
- **A shortened history.** The producer signs the tree, so a producer who removes entries and
  re-signs a smaller tree passes every check in a version-2 bundle. Nothing inside the pack can
  catch it.

Both additions are optional. A version-3 bundle with no redacted entries and no witnessed size is
byte-identical to a version-2 bundle except for `format`.

### 10.0 `fieldDigests` — an optional diagnostic, and explicitly not a check

An entry MAY carry `fieldDigests`: a compact JSON object mapping each of `at`, `action`, `outcome`
and `environment` to the first 12 hex characters of the SHA-256 of that field as it was written:
`at` rendered as `%.6f`; the others as their string value, with an absent or null field rendering
as the empty string.

`at` is a number in a well-formed entry and may be anything at all in a tampered one, so an
implementation MUST NOT raise when it does not parse — it renders as `unparseable:<repr>` and the
digest simply does not match, which is the right answer because the field *has* changed. A verifier
that throws here reports "the tool is broken" where it should report "entry N was edited", and that
is a one-character way to make a forgery read as a tooling problem. A pack is JSON and JSON integers
are unbounded, so the overflow case (`float(10**400)`) is part of that MUST and not an edge case;
the same rendering rule applies to the `survivingDigest` of §10.1, which commits to the same field.

The three non-`at` fields render as their string value, and **only a null or absent field renders as
the empty string**. `0`, `false`, `[]` and `{}` are not the empty string. Collapsing them was a real
defect: `environment` is genuinely `""` on redaction and seal entries, so an entry edited to `0`
kept a matching digest while its hash broke, and the verifier then made the positive — and wrong —
claim that the change lay in one of the six uncommitted fields.

A verifier that finds an entry's contents do not match its hash MAY recompute these and name the
fields that no longer agree, so a report can say *"entry 4,712: outcome changed"* rather than
*"entry 4,712 does not match its hash"*.

Three requirements, and the third is the point:

1. `fieldDigests` is **never** part of the entry hash. A bundle with it and one without hash
   identically, so it is additive within version 3 and a verifier that ignores it is conformant.
2. A verifier MUST NOT treat agreement here as evidence of anything. It is a derived value that
   whoever edited the row could also have edited. **Detection is the chain and only the chain**;
   this narrows a search.
3. The list is exactly the four fields a redaction leaves readable, and MUST NOT be extended to
   `actor`, `actorId`, `target`, `reason`, `detail` or `sourceIp`. A short digest of a low-entropy
   field is a dictionary oracle, and those six are precisely the fields an erasure removes — a
   commitment over them would hand the content of every redacted entry to anyone holding the pack.

A verifier reporting a broken entry hash therefore has **three** answers, and MUST keep them
distinct:

| what it found | what it MUST say |
| --- | --- |
| one or more digests disagree | at least these fields changed — and that the six uncommitted fields may have changed too |
| every digest agrees | the change is in one of the six that carry no per-field commitment |
| the entry carries no `fieldDigests` | which field changed cannot be said |

The third is not a softer version of the second. `fieldDigests` is per **entry**, not per pack: a
log upgraded from a schema that predates it legitimately mixes entries that carry digests with
entries that do not, and an entry's column can also be blanked by the same edit that broke its hash.
Answering either with the second row's sentence is a positive claim about where the change is *not*,
and sends a reader to diff exactly the fields that did not change.

### 10.1 A redacted entry

An entry whose content has been erased carries two extra keys:

```json
{"seq": 12, "action": "decision.resolve", "outcome": "allowed",
 "actor": "[redacted]", "target": "[redacted]", "reason": "[redacted]",
 "actorId": "", "sourceIp": "", "detail": {},
 "redacted": true, "redactedAt": 1757600400.0,
 "prevHash": "aaaa…", "hash": "3f5f…"}
```

Its `hash` is unchanged — erasure does not rewrite the chain, so the entry keeps its place, its
linkage and its Merkle leaf. Its content cannot be recomputed, so a verifier MUST NOT attempt the
version-1 hash check on it, and MUST instead check all three of:

1. **It looks erased.** `actor`, `target` and `reason` are exactly `"[redacted]"`; `actorId`,
   `sourceIp` are empty; `detail` is `{}`. An entry claiming erasure while carrying content has not
   been through one.
2. **An authorising entry is present** in the same pack: an entry with `action` `"audit.redact"`
   whose `detail.redactedSeq` equals this entry's `seq`. That entry is an ordinary entry, hashed
   and Merkle-proven like any other, so it cannot be forged without breaking a hash the verifier
   does recompute.
3. **The fields erasure left readable are the ones it authorised**, by comparing
   `detail.survivingDigest` of the authorising entry against the digest defined below.

A verifier that skips (2) or (3) is not implementing version 3: without them, setting `redacted`
on an entry is a way to rewrite its action, outcome, environment and time and still pass.

#### The surviving digest

`at`, `action`, `outcome`, `environment`, `prev_hash` and `hash` survive an erasure — removal must
take what identifies a person, not the fact that an action occurred. They are committed to as:

```
survivingDigest = SHA-256(canonical({
    "action": <action>, "at": <at>, "environment": <environment>,
    "hash": <hash>, "outcome": <outcome>, "prev_hash": <prevHash>}))
```

`canonical` is §3's encoding: sorted keys, `(",", ":")` separators, UTF-8. `at` is a JSON number,
the other five are strings. Note the snake_case keys `prev_hash` and `hash`: the digest is computed
over the producer's row shape, not the pack's camelCase (§4.2).

**Test vector.**

```
{"action":"decision.resolve","at":1757600000.0,"environment":"production","hash":"3f5f0c8a2f2f0a9d1b6d2e4c8a7b9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708","outcome":"allowed","prev_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
survivingDigest = e1df34a93e07f27588dbc727a7874b5fad2e98476e1223477803ff88aa640664
```

The producer MUST refuse to redact an entry that does not already verify under §3. Taking the
commitment over a row that had been edited first would have the erasure certify the edit.

### 10.2 A consistency proof against a witnessed size

When a witness has cosigned an earlier size of this log, `merkle.witnessed` carries the proof that
the current tree extends it:

```json
"witnessed": {
  "witness": "underwrit/witness-1", "size": 812, "root": "9c1d…", "at": 1757600000.0,
  "cosignedNote": "underwrit/node-1\n812\nnBB1…\n\n— underwrit/witness-1 <base64>\n",
  "consistency": {"oldSize": 812, "newSize": 1041, "oldRoot": "9c1d…", "newRoot": "4ae0…",
                  "proof": ["…", "…"]}
}
```

`proof` is an RFC 9162 §2.1.4 consistency proof from `oldSize` to `newSize`, hex-encoded. A
verifier MUST check all of:

1. The proof verifies from `oldRoot`@`oldSize` to `newRoot`@`newSize` (RFC 9162 §2.1.4.2).
2. `newRoot` and `newSize` equal the checkpoint's root and size — otherwise the proof is against a
   different tree than the one the pack is about.
3. `cosignedNote` parses as a §9.2 checkpoint note whose size and root equal `oldSize`/`oldRoot`.
4. A cosignature on that note verifies under a witness key the verifier obtained **out of band**.

**Without (4) the structure proves nothing**, and a verifier MUST say so rather than report a pass:
`oldSize` and `oldRoot` come from the producer, so an unpinned proof shows only that the producer's
tree extends a prefix of the producer's tree. Only a cosignature from a party the operator does not
control turns it into a statement about completeness.

### 10.3 A seal

A seal ends one tree and starts another (§9.1 covers only the live log), so after one the witnessed
size is legitimately beyond the current tree. `witnessed.supersededBySeal` carries what the
`audit.seal` entry recorded — `{"size", "root", "archive"}`.

A verifier MUST NOT treat this as either a pass or a failure. An `audit.seal` entry is an ordinary
entry that anyone who can write the log can append, and nothing in the bundle checks its stated
size or root against anything, so a rollback dressed as a seal is indistinguishable from inside the
pack. Report it as unchecked, name the archive, and — where a witness key is pinned — refuse.

### 10.4 What version 3 proves, and what it still does not

Added: that an erasure was authorised and did not rewrite what it left behind; and, with a witness
key pinned, that nothing recorded before the witnessed size has been removed since.

Still not proven: completeness of the pack itself (a producer chooses which entries to include);
that a seal was a seal; and origin, without a key from `GET /v1/keys` obtained out of band.

### 10.5 Test vectors

The surviving digest: §10.1 above, asserted by `tests/test_conformance.py`. Consistency proofs:
RFC 9162 §2.1.5, asserted by `tests/test_evidence_v2.py`. The end-to-end behaviours — a redacted
entry verifying, a forged one failing, an unpinned consistency proof declining to claim
completeness — are in `tests/test_redaction_evidence.py` and `tests/test_rollback_and_workers.py`.

### 10.6 Approval entries: `detail` keys the reference implementation records

Not part of the format — `detail` is hashed as an object whatever it holds (§2) — but a reader of
a reference-implementation pack meets these on `decision.approval` and `decision.resolve` entries
and should know what each one claims. Every value is a name, a flag or a digest; none is an
argument value.

| entry | key | meaning |
| --- | --- | --- |
| `decision.approval` | `identifiedVia` | how the approver proved who they are: `oidc`, `spiffe`, `break-glass`, `token` |
| `decision.approval` | `countsTowardQuorum`, `localApproversAllowed`, `onePersonEnvironment` | whether and why this answer counts |
| `decision.approval` | `acknowledgedFields` | the tool-sourced argument fields an `allow` named in `acknowledged`; `[]` on a `deny` or where none was required |
| `decision.approval` | `requesterExcluded` | subjects whose approval rows were dropped from the count because they are the requester (present only when one was) |
| `decision.approval` (outcome `refused`) | `attempted`, `refusedBecause` | an `allow` that was not recorded as an answer, and why: `frozen`, `requester`, or `unacknowledged` (with `authorityStatus`, `authorityFields`, `unacknowledged` — field names) |
| `decision.resolve` | `answers`, `settledBy`, `approvers` | every counted answer with its verdict and `via`; who cast the settling verdict |
| `decision.resolve` | `acknowledgedFields` | the union of `acknowledgedFields` across the counted `allow` answers |
| `decision.resolve` | `requesterExcluded` | as above, at settlement |

A refused `allow` is an entry with outcome `refused` and **no** row in the approvals ledger: it
settles nothing and is never counted, and the entry is the only trace of it, which is the point.

### 10.7 Decision entries: `detail` keys added in the 1.0 reference implementation

Additive within version 3, like §10.6: `detail` is hashed as an object whatever it holds, so a
version 3 verifier that has never heard of these keys verifies these entries exactly as before, and
is conformant. Every value is a name, a count or a digest.

| entry | key | meaning |
| --- | --- | --- |
| `decision` | `codes` | one stable code per reason, in the same order, from the registry the reference implementation serves at `GET /v1/gates` (`underwrit/codes.py`) |
| `decision` | `usageUnits` | the units of the usage the runtime reported for this call (`["usd"]`); the amounts stay on the plane's decision row |
| `decision` | `delegation` | `{"depth", "digest"}`: how many agents stood behind the proposal, and SHA-256 over the canonical JSON of the chain the runtime sent |
| `decision` | `components` | `{"keys", "digest"}`: the names in the component manifest the runtime declared (model, prompt digest, tool versions) and SHA-256 over its canonical JSON |
| `decision` | `confidential` | how many confidential sources the session had read when it proposed this action |
| `decision` | `compensates` | the id of the earlier decision this one proposes to undo or repair; such a decision carries the code `compensation.proposed` |
| `decision.compensate` | `decisionId`, `compensation`, `basis` | a compensation was proposed: the original, the new decision, and why it was allowed (`uncertain`, `verification_failed` or `scope_held`). `reason` holds the proposer's explanation |
| `decision.approval` | `prediction` | under a prediction gate: `{"fields", "mismatched", "confirmedMismatch"}` — field names the approver predicted, those that did not match, and whether they approved anyway. Never what they predicted |
| `decision.approval` (outcome `refused`) | `refusedBecause` | adds `prediction-required` (with `predictionMissing`) and `prediction-mismatch` (with `predictionMismatched`) |
| `decision.verify` | `late` | `true` when the verification arrived on its own after the outcome (`POST /v1/verify`) |
| `decision.verify_overdue` | `dueAt`, `holdTarget` | a post-hoc verification the policy required that nobody recorded by its deadline, and whether the target was held for it |

---

## 11. Version 4: a session's missing entries show

Versions 1 to 3 prove that every entry present is unaltered and sits where the log put it. They do
not prove that a session's pack holds all of that session's entries: its entries are interleaved
with every other session's, so a gap in sequence numbers is normal, and an entry removed by someone
holding the log key leaves nothing behind. Version 4 adds two structures that make removal visible,
and one ordering rule.

### 11.1 The session link

An entry whose `detail` names a scope (the first of `sessionId`, `runId`, `subjectId`, `requestId`
that is a non-empty string) carries `scopePrev`: the `hash` of the previous entry with the same
scope, or 64 zeros for the scope's first entry. It is part of the hashed payload under the key
`scope_prev`:

    payload = {at, actor, actor_id, action, environment, target, outcome, reason, detail, source_ip,
               scope_prev}

`scope_prev` is present only when it is non-empty, so an entry without one hashes exactly as in
version 1. It survives redaction, and the surviving digest (§10.1) includes it when present.

A verifier groups the pack's entries whose scope is the pack's `subject.id` (taken from `detail` for
a readable entry, and from the derived `scope` field for a redacted one; the two must agree where
both exist) and requires each `scopePrev` to equal the `hash` of the group's previous entry in the
pack, or 64 zeros when there is none. Entries without a link (written before version 4) are allowed
and the verifier says how many there are.

### 11.2 Session heads

A checkpoint may carry one extension line after the root:

    underwrit-scopes <count> <root, base64>

The root is an RFC 6962 Merkle tree over one leaf per scope among the checkpoint's first `size`
entries, sorted by the scope's UTF-8 bytes:

    leaf = SHA-256(0x00 ‖ "underwrit-scopes\n" ‖ scope ‖ "\n" ‖ seq ‖ "\n" ‖ hash)

where `seq` and `hash` are that scope's latest entry at that size. No other extension line is
permitted. The pack carries `merkle.scopeHeads.checkpoint` (against the checkpoint it ships) and,
when it ships a consistency proof to a witnessed size, `merkle.scopeHeads.witnessed`, each:

    {size, count, root, proofs: [{scope, present: true, seq, hash, index, proof}
                                 | {scope, present: false, left, right}]}

A present head must verify against the note's root, and the pack must contain an entry with that
`seq` and `hash`. An absent one is shown by the leaves either side (`left`, `right`, each a present
leaf, either may be null at the tree's edge) at adjacent indices, whose scopes bracket the subject's.
A note with the line and no proof for the subject is a failure: the commitment exists and the pack
declines to use it.

### 11.3 Order

`auditEntries` is in strictly increasing `seq` order. This applies to every version: an honest
producer has always written that order.

### 11.4 What version 4 proves, and what it still does not

With the witness's key pinned, a pack whose session heads were cosigned proves that no entry of the
subject's session up to the witnessed size has been removed. Entries after that size rest on the log
key alone. A holder of the log key who also rewrites the database and re-checkpoints produces a pack
the log key accepts and a pinned witness refuses, as in version 3. The heads say nothing about
sessions other than the pack's subject.

