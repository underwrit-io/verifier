# The Underwrit witness protocol

Version 1. MIT, like the evidence format — a witness nobody else can implement is not a witness.
(The Underwrit product itself is proprietary; this document and the verification code are carved
out under MIT and published as the public Underwrit verifier.)

A witness is a second party that watches a log grow and signs what it saw. It never sees an entry,
an argument, or a session: it sees a size, a root, and a signature. That is deliberate, and it is
what lets the witness be somebody with no business relationship to the log's operator.

This document specifies two exchanges:

1. **Cosigning a checkpoint** — C2SP's [tlog-witness](https://c2sp.org/tlog-witness), as this
   product speaks it.
2. **Cosigning a seal** — new here, and the reason this document exists. A log that archives its
   history and starts again takes its Merkle tree back to size zero, which from outside is
   byte-identical to a log that deleted its history. Nothing in the C2SP protocols distinguishes
   them, and without a distinction an evidence bundle taken after a lawful seal can only say
   "NOT CHECKED".

---

## 1. What a witness establishes, and what it does not

A witness cosignature says: *at time T, the largest consistent tree I have seen for this log had
this size and this root.* It establishes that the log has not been **shortened or rewritten** behind
the witness's back, because a log that rewrites history cannot produce a consistency proof from a
root the witness already signed.

It does **not** establish that the log is complete, that its entries are true, or that the operator
is honest about anything else. A witness that has seen nothing since size 400 says nothing about
entries 401 onward.

It also does **not** establish that a tree was ever real. A witness sees sizes and roots; it cannot
tell a log with entries behind it from one invented in memory, at enrolment or afterwards, and a
fabricated tree can be extended with a perfectly valid RFC 9162 consistency proof. **Enrolment is
trust on first use**: the first checkpoint a witness sees for a node has no prior root to be checked
against, so the witness takes the node's word for it and everything after that is measured from
there. What the protocol delivers is narrower and still worth having: a log cannot change history
this witness has already seen.

Two consequences follow, and both are rules below rather than caveats. A node's identity here is the
credential that first reported it (§3.1 step 3), because otherwise the "node" whose history is being
protected is a string the caller chooses. And a seal may only close a head the witness reached
through a proof, never one it merely accepted at first contact (§4.2 step 4) — otherwise a seal is a
way to have a witness sign for a tree it was simply handed.

A single witness is a single point of trust. `UNDERWRIT_WITNESSES` takes several; a checkpoint
cosigned by N independent witnesses requires N collusions rather than one.

---

## 2. Notes

Both exchanges carry [C2SP signed notes](https://c2sp.org/signed-note). A note is a body, a blank
line, and one or more signature lines:

```
<origin>
<size>
<root, base64 of 32 bytes>
[<additional lines, origin-defined>]

— <name> <base64(key hash ‖ signature)>
```

The root is exactly 32 bytes; a note whose third line decodes to anything else is malformed and
MUST be refused, by every implementation, before any signature is considered.

The signed bytes are the body **including every additional line and the trailing newline**, and
excluding the blank line and the signatures. An implementation that reconstructs only the first
three lines will fail to verify a note that has more, which is the intended behaviour: a verifier
must not sign off on bytes it did not read.

The key hash is `SHA-256(name ‖ 0x0A ‖ alg ‖ public key)[:4]`, with `alg = 0x01` for an Ed25519 log
signature and `0x04` for a cosignature. The two algorithm bytes exist so a reader can tell a log
line from a witness line without knowing either key.

A **cosignature** signs

```
cosignature/v1
time <unix seconds>
<the note body>
```

and its signature line's blob is `key hash[4] ‖ time (8 bytes, big-endian) ‖ signature (64 bytes)`.

### 2.1 Ed25519

Signatures are Ed25519 (RFC 8032). Verification MUST be **strict**: reject non-canonical point
encodings for both `A` and `R` (any `y ≥ p`), reject `s ≥ L`, reject small-order `A` and `R`, and
use the cofactored equation `[8][s]B = [8]R + [8][h]A`.

This is stricter than RFC 8032 requires, and it is required here because two implementations that
each follow RFC 8032 can disagree about a crafted signature — which for a transparency log means a
bundle that verifies for the issuer and fails for the auditor. The strict rules above are the
intersection: every signature an honest signer produces passes them, and the cases where
implementations part company do not.

---

## 3. Checkpoints

A checkpoint note's origin is the log's name, its size is the number of leaves, and its root is the
RFC 9162 Merkle root over them:

```
underwrit/node-1
519
9csWKa45f+RopbeuBfM1372U5iFpvUPROpR2ilIGK7Q=

— underwrit/node-1 <base64(key hash ‖ signature)>
```

The leaf for entry *i* is `SHA-256(0x00 ‖ hash_i)`, where `hash_i` is the entry's chain hash **as
its 64 ASCII hex characters**, not as 32 bytes. The tree therefore commits to exactly what the chain
commits to.

### 3.1 The exchange

```
POST /v1/witness
{ "node": "node-1", "checkpoint": "<note>", "logKey": "<base64 public key>",
  "oldSize": 400, "consistency": ["<hex>", …] }
```

The witness MUST, in order:

1. Refuse a note whose origin begins `underwrit-seal/`. A seal is not a checkpoint, and this route
   performs none of §4's checks — without this rule it is an oracle for cosigned seal notes, and
   the domain separation in §4.1 separates nothing.
2. Refuse a checkpoint note carrying additional body lines. A checkpoint's body is exactly the
   three lines of §2; a witness must not cosign bytes it cannot account for. (§2's additional lines
   are for origins that define them, and this origin does not.)
3. Refuse unless the reported node name belongs to the credential that first reported it. `node` is
   a string the caller chooses; without this every rule below checks a pin the caller created.
4. Refuse unless `logKey` is 32 bytes.
5. Refuse if it has a key pinned for this node and `logKey` differs from it. A log key changes
   through an operator, never through a report; otherwise a node re-keys itself and the witness's
   whole history of it becomes worthless.
6. Refuse if it has an origin pinned for this node and the note's origin differs from it.
7. Refuse unless the note verifies under `logKey` for the note's own origin.
8. If it has no record of this node, require `oldSize` to be 0 or absent.
9. If it has a record, refuse unless `oldSize` equals the size it last cosigned. (The node's copy of
   that can be stale; a refusal carrying the witness's size lets the node retry.)
10. Refuse if the new size is smaller than the witnessed size — **the log shrank** — unless §4 applies.
11. If the new size equals the witnessed size, require the same root, and return the existing
    cosignature unchanged.
12. Refuse unless `consistency` proves, per RFC 9162 §2.1.4.2, that the witnessed tree is a prefix of
    the new one. Where the witnessed size is 0 there is nothing to prove: the empty tree is a prefix
    of every tree.
13. Cosign, record, and return.

A refusal at step 12 is the finding the protocol exists to produce: the witness holds a root the log
can no longer reach. It MUST carry the size and root the witness expects, so the operator can see
exactly where the histories part.

---

## 4. Seals

A **seal** archives the live chain and starts a new one. The tree covers the live chain only, so a
seal takes the size back to zero. Steps 5, 6 and 8 above would refuse every checkpoint afterwards,
and correctly — from outside, this is what deleting the evidence looks like.

So a seal is an explicit, signed, witnessed event.

### 4.1 The seal note

Origin `underwrit-seal/<node>`, distinct from the checkpoint origin `underwrit/<node>` so that a
seal note can never be presented as a checkpoint or the reverse. Size and root are the tree being
**closed**. Two additional lines follow:

```
underwrit-seal/node-1
4
GiwbBTIyE9PXS2yXlU0IiJmi6ZavhO26VZ8b2TSuS9M=
archive 5b1f9d3c0f39e0a3a7bbd7e63a6b1f2c8d4e5a6b7c8d9e0f1a2b3c4d5e6f7a8b
epoch 0

— underwrit-seal/node-1 <base64(key hash ‖ signature)>
```

- `archive <hex>` — SHA-256 of the archive file's contents, 64 lower-case hex characters. The same
  digest appears in the seal manifest and in the `audit.seal` entry that opens the new chain.
- `epoch <n>` — the epoch being closed. A log begins at epoch 0; the *n*th seal closes epoch *n−1*.

Both lines are part of the signed body. A reader MUST refuse a seal note missing either.

### 4.2 The exchange

```
POST /v1/witness/seal
{ "node": "node-1", "sealNote": "<note>", "logKey": "<base64 public key>" }
```

The witness MUST, in order:

1. Refuse unless `logKey` is 32 bytes.
2. Refuse unless it already holds a checkpoint for this node. A log the witness has never seen has
   nothing here to seal.
3. Refuse unless the reported node name belongs to the credential that first reported it (§3.1
   step 3).
4. **Refuse unless the head being closed was PROVEN rather than asserted** — that is, unless the
   witness accepted it on a verified consistency proof (§3.1 step 12) rather than at first contact.
   At first contact there is no prior root, so the witness cosigns whatever size it is handed; a
   seal accepted on the strength of that is a way to have a witness sign for a tree it was simply
   given. This is a property of the *head*, not a count of exchanges: a seal resets the head to
   zero, and the checkpoint after a seal is accepted without a proof for the same reason first
   contact is — so a witness that counted exchanges instead handed every epoch after the first one
   back its free unproven cosignature. The flag resets with the head.
5. Refuse unless `logKey` equals the pinned key.
6. Refuse unless the note is a seal note (origin begins `underwrit-seal/`), verifies under `logKey`,
   and carries both additional lines, each stated exactly once.
7. Refuse unless the origin corresponds to the node's pinned log origin. A node with no origin
   pinned — one carried forward from before this rule — is refused and told to report a checkpoint,
   which pins it.
8. If a seal is already recorded for the epoch **the note names**: return the existing cosignature
   if the note is byte-identical, and refuse otherwise. This check comes before step 7, because a
   node re-sending a seal it has already had cosigned is the ordinary case when an answer was lost
   — and by then the epoch has moved on *because of that seal*.
9. Refuse unless the note's epoch is the node's current epoch.
10. **Refuse unless the note's size and root are exactly the size and root this witness last
    cosigned.** This is the rule the whole mechanism rests on: a node whose live log has grown past
   the witnessed size must obtain a cosignature at the size it intends to close *before* closing
   it. Without this step, sealing would be a way to make unwitnessed entries disappear.
11. Cosign the seal note, record it permanently, set the node's head to size 0 with an empty root,
    and advance its epoch.

The refusal at step 10 MUST carry the size and root the witness holds, and say that a checkpoint at
the intended size must come first.

### 4.2.1 Re-pinning

An operator route that re-pins a node's log key MUST clear everything trust rested on — the pinned
origin, the credential binding, the head, and whether that head was proven — and MUST NOT touch the
recorded seals. Leaving the first group behind creates a node that can never report again: a changed
origin no later report can match. Clearing the seals creates the mirror of it, because a node's own
epoch only ever climbs, so a witness rewound to epoch 0 refuses that node's next seal forever. The
epoch is therefore **derived from the seal ledger** rather than reset beside it.

The ledger is also the witness's own account of what it agreed to, and the only thing a later
auditor can be shown about a closed epoch. Re-pinning MUST be available only to an operator of the
witness — never to the party whose log is being witnessed. A record its subject can erase is not a
record.

### 4.3 After a seal

The node's next checkpoint is judged against an empty tree: `oldSize` is 0 and no consistency proof
is required or checked. The witness's record of previous epochs is not discarded — it is what a
later bundle uses.

---

## 5. What a bundle carries, and what a verifier decides

An evidence bundle whose tree is *smaller* than a size the witness has cosigned carries, in
`merkle.witnessed`:

- `supersededBySeal` — the log's own account, from the `audit.seal` entry: the size it closed and
  the archive it wrote. **This is not evidence.** An `audit.seal` entry is an ordinary append;
  whoever can delete a history can write one claiming to have archived it.
- `sealLineage` — one record per seal, each with `epoch`, `size`, `root`, `archiveSha256`,
  `witness` and `cosignedNote`. A record whose `cosignedNote` is empty is an unwitnessed seal, and
  is worth exactly as much as `supersededBySeal`.

A verifier with a pinned witness key MUST resolve the gap as follows:

1. Find the lineage records whose `size` **and** `root` equal the witnessed size and root. Matching
   on size alone is not sufficient: a different epoch's seal could share a size.
2. For each such record with a cosignature: verify the log's own signature over the seal note under
   the pinned log key; verify that the note's size and root are the witnessed ones; verify a
   cosignature by a pinned witness key.
3. If one verifies, the gap is explained — and **nothing else is**. A seal attests the *closing*
   tree of a past epoch; the entries in the bundle are in the epoch after it. A verifier that let a
   seal satisfy a pinned witness key made a witnessed seal a permanent excuse for every later
   rollback: rewind the record of what the witness saw to the epoch boundary, delete whatever it
   cosigned since, and the pack says "the check a rollback cannot pass". The pinned-witness
   requirement still needs a cosignature on this checkpoint, or a consistency proof to a cosigned
   root inside the current epoch.
4. The archive digest and the epoch MUST be read from the signed note, never from any JSON beside
   it, and the seal offered MUST close the epoch immediately before the bundle's own.
5. If a candidate record fails any check, that is a failure, not a fall-through. A cosignature over
   a seal signed by some other key proves nothing about this log.
6. If there is no cosigned candidate, report the gap as **not checked**: the verifier cannot tell a
   lawful seal from a shortened history, and must not imply that it can. With a witness key pinned
   this is a failure.

Without a pinned witness key, a cosignature is a line the producer could have written, and the
verifier MUST say so rather than counting it.

---

## 6. Test vectors

A witness key and a log key, both Ed25519 seeds of 32 bytes:

```
log seed     = 0000000000000000000000000000000000000000000000000000000000000000
log public   = O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=
witness seed = 0101010101010101010101010101010101010101010101010101010101010101
witness pub  = iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=
```

A seal note closing a tree of size 4 whose root is 32 zero bytes, archive digest `ab…ab`, epoch 0,
signed by the log key:

```
underwrit-seal/node-1
4
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
archive abababababababababababababababababababababababababababababababab
epoch 0

— underwrit-seal/node-1 L9nPOko679qfKCgrxRf4SvM1ZoOuAET9kCp4pQ1TUTOFP3r4jxkHYoKxxs6nFIajq90oChSxvypsSlyWW+6uLUp9eQk=
```

The signed bytes are everything from `underwrit-seal/node-1` through the newline after `epoch 0`,
and their SHA-256 is:

```
sealBodySha256 = 4eb8ab7855b4aa807c937964d4846faf3ab2f19c99f533ad872d147b29cd8b13
```

`tests/test_seal_protocol.py` and `tests/test_conformance.py` parse these out of this document, so
the specification and the implementation cannot drift apart without a test failing.

---

## 7. Versioning

This document is version 1 of the witness protocol. The checkpoint exchange in §3 is C2SP's and
changes with it; §4 is this protocol's own and follows the same rule as the evidence format: a
change that alters any signed byte for the same logical event is a new version, never an amendment.
