/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Underwrit
 *
 * MIT, although the rest of Underwrit is proprietary. Take it, embed it, ship it.
 *
 * An Underwrit evidence verifier that runs entirely in the page.
 *
 * The second implementation of the format, which is the only way to find out whether the
 * specification is a specification or a description of one program. Written from
 * spec/evidence-format.md; everything it needs is in the browser — no library, no upload, no
 * account, nothing leaves the machine.
 *
 * Deliberately says the same things `verify.py` says, in the same words, including the parts that
 * are not reassuring. A verifier that overstates itself is worse than none.
 */

const GENESIS = "0".repeat(64);

/* ---- canonical JSON (spec §3) ----------------------------------------------------------- */

/* CPython's repr() of a float, which is what `json.dumps` emits for one — and what every entry
 * hash in this format is computed over. `JSON.stringify` writes 1757600000 where Python writes
 * 1757600000.0, so a whole-second timestamp hashes differently in the two languages. That is the
 * single thing standing between this format and a second implementation. */
export function pyNumber(n) {
  if (!isFinite(n)) throw new Error("non-finite number in an entry");
  const a = Math.abs(n);
  if (a !== 0 && (a >= 1e16 || a < 1e-4)) {
    let [m, e] = n.toExponential().split("e");
    const sign = e[0] === "-" ? "-" : "+";
    e = e.replace(/^[+-]/, "");
    if (e.length < 2) e = "0" + e;
    return m + "e" + sign + e;
  }
  if (Number.isInteger(n)) return n.toFixed(1);
  return String(n);
}
/* JSON gives no way to know whether `3` was `3` or `3.0` in the producer, and the two hash
 * differently. The format puts a float in exactly one place — `at`, spec §3 — so that key is
 * written as a float and every other number as an integer. Any future float-valued field has to be
 * added here *and* to the spec, or the two implementations silently diverge on entries containing
 * it. */
const FLOAT_KEYS = new Set(["at"]);

export function canonical(value, key) {
  if (value === null) return "null";
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") return FLOAT_KEYS.has(key) ? pyNumber(value) : pyInt(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map((v) => canonical(v)).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(value[k], k)).join(",") + "}";
}
function pyInt(n) {
  if (Number.isInteger(n)) return String(n);
  return pyNumber(n);
}

/* ---- primitives ------------------------------------------------------------------------- */

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));
async function sha256(bytes) { return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)); }
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

async function entryHash(prev, payload) {
  return hex(await sha256(enc.encode(prev + canonical(payload))));
}

/* RFC 9162 §2.1: leaves are 0x00-prefixed, nodes 0x01-prefixed. */
const leafHash = (b) => sha256(concat(new Uint8Array([0]), b));
const nodeHash = (l, r) => sha256(concat(new Uint8Array([1]), l, r));

async function rootFromInclusion(index, size, leaf, proof) {
  if (index >= size) throw new Error("leaf index outside the tree");
  let [fn, sn, node] = [index, size - 1, leaf];
  for (const sibling of proof) {
    if (sn === 0) throw new Error("inclusion proof is longer than the tree is deep");
    if (fn % 2 === 1 || fn === sn) {
      node = await nodeHash(sibling, node);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      node = await nodeHash(node, sibling);
    }
    fn >>= 1; sn >>= 1;
  }
  if (sn !== 0) throw new Error("inclusion proof is shorter than the tree is deep");
  return node;
}

async function verifyConsistency(oldSize, newSize, oldRoot, newRoot, proof) {
  if (oldSize < 1 || oldSize > newSize) return false;
  if (oldSize === newSize) return proof.length === 0 && hex(oldRoot) === hex(newRoot);
  let [fn, sn] = [oldSize - 1, newSize - 1];
  while (fn % 2 === 1) { fn >>= 1; sn >>= 1; }
  let [fr, sr] = [null, null];
  let rest = proof.slice();
  if (fn !== 0) { fr = rest.shift(); sr = fr; } else { fr = oldRoot; sr = oldRoot; }
  if (!fr) return false;
  for (const c of rest) {
    if (sn === 0) return false;
    if (fn % 2 === 1 || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      while (fn % 2 === 0 && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && hex(fr) === hex(oldRoot) && hex(sr) === hex(newRoot);
}

/* ---- the zip ----------------------------------------------------------------------------- */

/* Parsed by hand rather than with a library: the point of this page is that it needs nothing.
 * DEFLATE comes from the platform's own DecompressionStream. */
async function readZip(buffer) {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  let eocd = -1;
  for (let i = buffer.byteLength - 22; i >= 0 && i > buffer.byteLength - 65558; i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error("not a zip file");
  const count = view.getUint16(eocd + 10, true);
  let at = view.getUint32(eocd + 16, true);
  const files = {};
  for (let n = 0; n < count; n++) {
    if (view.getUint32(at, true) !== 0x02014b50) throw new Error("damaged central directory");
    const method = view.getUint16(at + 10, true);
    const compSize = view.getUint32(at + 20, true);
    const nameLen = view.getUint16(at + 28, true);
    const extraLen = view.getUint16(at + 30, true);
    const commentLen = view.getUint16(at + 32, true);
    const localAt = view.getUint32(at + 42, true);
    const name = new TextDecoder().decode(bytes.subarray(at + 46, at + 46 + nameLen));
    const lNameLen = view.getUint16(localAt + 26, true);
    const lExtraLen = view.getUint16(localAt + 28, true);
    const dataAt = localAt + 30 + lNameLen + lExtraLen;
    const raw = bytes.subarray(dataAt, dataAt + compSize);
    files[name] = method === 0 ? new Uint8Array(raw) : await inflate(raw);
    at += 46 + nameLen + extraLen + commentLen;
  }
  return files;
}

async function inflate(raw) {
  if (typeof DecompressionStream !== "function") {
    throw new Error("this browser cannot decompress the bundle (no DecompressionStream)");
  }
  const stream = new Blob([raw]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/* ---- checkpoint notes (spec §9.2) -------------------------------------------------------- */

function scopeOf(detail) {
  for (const k of ["sessionId", "runId", "subjectId", "requestId"]) {
    const v = detail && typeof detail === "object" ? detail[k] : undefined;
    if (typeof v === "string" && v) return v;
  }
  return "";
}

/* Scopes are ordered by their UTF-8 bytes (§11.2), which JavaScript's `<` on strings is not. */
function byteCmp(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

/* §11.2: the one extension line a checkpoint may carry. */
function parseScopesLine(extra) {
  if (!extra.length) return null;
  if (extra.length !== 1) throw new Error("a checkpoint carries at most one extension line");
  const parts = extra[0].split(" ");
  if (parts.length !== 3 || parts[0] !== "underwrit-scopes" || !/^[0-9]+$/.test(parts[1])) throw new Error("unrecognised extension line");
  const root = Uint8Array.from(atob(parts[2]), (c) => c.charCodeAt(0));
  if (root.length !== 32) throw new Error("the scopes root is 32 bytes");
  return { count: parseInt(parts[1], 10), root };
}

function parseNote(text) {
  const [body, sigs = ""] = text.split("\n\n");
  const lines = body.split("\n");
  if (lines.length < 3) throw new Error("checkpoint note is too short");
  const signatures = [];
  for (const line of sigs.split("\n")) {
    if (!line.startsWith("— ")) continue;
    const [, name, blob] = line.split(" ");
    const rawSig = Uint8Array.from(atob(blob), (c) => c.charCodeAt(0));
    signatures.push({ name, keyHash: hex(rawSig.subarray(0, 4)), sig: rawSig.subarray(4) });
  }
  return {
    origin: lines[0],
    size: parseInt(lines[1], 10),
    root: Uint8Array.from(atob(lines[2]), (c) => c.charCodeAt(0)),
    body: body + "\n",
    extra: lines.slice(3),
    signatures,
  };
}

async function ed25519Verify(pub, msg, sig) {
  try {
    const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, msg);
  } catch (e) {
    return null;   // the browser has no Ed25519; "cannot check" is not "fails"
  }
}

/* The build statement (spec §12): what produced the pack, as the producer states it. Reported as
   notes and warnings, never as a failure: it says which edition and licence made the pack and
   whether the code was the release Underwrit signed. Mirrors `build_lines` in verify.py. */
function buildLines(build) {
  const out = [];
  try {
    const b = build.build && typeof build.build === "object" ? build.build : {};
    const status = String(b.status || "unknown");
    out.push([`Underwrit ${build.version || "?"}, ${build.edition || "?"} edition, licence ${build.licence || "none"}, ${status} build (code ${String(b.hash || "-").slice(0, 16)})`, false]);
    if (["modified", "unsigned", "unknown"].includes(status)) out.push([`modified build: ${b.reason || "its code is not the release Underwrit signed"}`, true]);
    else if (status === "source") out.push(["not a release build: it ran from a source checkout", true]);
    const cp = build.controlPlane && typeof build.controlPlane === "object" ? build.controlPlane : null;
    for (const [who, st] of [["this install", build], ["its control plane", cp]]) {
      if (!st) continue;
      const cb = st.build && typeof st.build === "object" ? st.build : {};
      if (st === cp && ["modified", "unsigned"].includes(cb.status)) out.push([`modified build: ${who} runs code that is not the release Underwrit signed`, true]);
      if (st.overLimit === true) {
        const lim = st.limits || {}, use = st.usage || {};
        const counts = `${who} counts ${use.tenants} team(s) and ${use.dataPlanes} data plane(s)`;
        if (lim.source === "free" || (st.licence || "none") === "none") out.push([`exceeds free limit: ${counts}; the free edition allows one of each`, true]);
        else out.push([`exceeds its licence: ${counts}, licensed for ${lim.tenants} and ${lim.dataPlanes}`, true]);
      }
    }
  } catch (e) {
    out.push(["the build statement is malformed", true]);
  }
  return out;
}

/* ---- the verification ---------------------------------------------------------------------
 * Returns {ok, lines: [{level, text}]}. `level` is "pass" | "note" | "warn" | "fail".
 */
export async function verifyBundle(buffer, { publicKey = "", witnessKey = "" } = {}) {
  const out = [];
  const problems = [];
  const say = (level, text) => out.push({ level, text });

  let files;
  try {
    files = await readZip(buffer);
  } catch (e) {
    return { ok: false, lines: [{ level: "fail", text: `${e.message}` }] };
  }

  const text = (name) => new TextDecoder().decode(files[name]);
  if (!files["manifest.json"]) return { ok: false, lines: [{ level: "fail", text: "manifest.json is missing — this is not a complete bundle" }] };

  const manifest = JSON.parse(text("manifest.json"));
  const format = manifest.format ?? 1;
  if (![1, 2, 3, 4].includes(format)) {
    return { ok: false, lines: [{ level: "fail", text: `this verifier understands formats 1 to 4, not ${format}` }] };
  }

  /* File digests. */
  for (const [name, expected] of Object.entries(manifest.files || {}).sort()) {
    if (!files[name]) { problems.push(`${name}: listed in the manifest but missing from the bundle`); continue; }
    if (hex(await sha256(files[name])) !== expected) problems.push(`${name}: content does not match its recorded digest`);
  }
  for (const name of ["evidence.json", "verify.py"]) {
    if (!(name in (manifest.files || {}))) problems.push(`${name}: not covered by the manifest`);
  }

  const pack = JSON.parse(text("evidence.json"));
  const entries = pack.auditEntries || [];

  /* Entries, and the redaction rules of §10.1. */
  const explained = {};
  for (const e of entries) {
    if (e.action === "audit.redact" && !e.redacted && e.detail && Number.isInteger(e.detail.redactedSeq)) {
      explained[e.detail.redactedSeq] = String(e.detail.survivingDigest || "");
    }
  }
  const surviving = async (e) => {
    const body = {
      action: String(e.action || ""), at: e.at, environment: String(e.environment || ""),
      hash: String(e.hash || ""), outcome: String(e.outcome || ""), prev_hash: String(e.prevHash || ""),
    };
    if (e.scopePrev) body.scope_prev = String(e.scopePrev); /* §11.1: the link survives an erasure */
    return hex(await sha256(enc.encode(canonical(body))));
  };

  let redactions = 0;
  for (const e of entries) {
    if (e.redacted) {
      redactions++;
      const leftover = ["actorId", "sourceIp"].filter((k) => e[k]);
      if (e.detail && Object.keys(e.detail).length) leftover.push("detail");
      if (!["actor", "target", "reason"].every((k) => e[k] === "[redacted]")) leftover.push("actor/target/reason");
      if (leftover.length) {
        problems.push(`audit entry seq ${e.seq}: marked redacted but still carries ${leftover.join(", ")} — that is not what a redaction leaves behind`);
      } else if (!(e.seq in explained)) {
        problems.push(`audit entry seq ${e.seq}: marked redacted with no \`audit.redact\` entry in this record authorising it`);
      } else if (explained[e.seq] !== await surviving(e)) {
        problems.push(`audit entry seq ${e.seq}: the fields this redaction left readable are not the ones the erasure authorised`);
      }
      continue;
    }
    const prev = e.prevHash || "";
    if (prev.length !== 64) { problems.push(`audit entry seq ${e.seq}: records no predecessor hash`); continue; }
    const payload = {
      action: String(e.action || ""), actor: String(e.actor || ""), actor_id: String(e.actorId || ""),
      at: e.at, detail: e.detail, environment: String(e.environment || ""),
      outcome: String(e.outcome || ""), reason: String(e.reason || ""),
      source_ip: String(e.sourceIp || ""), target: String(e.target || ""),
    };
    if (e.scopePrev) payload.scope_prev = String(e.scopePrev); /* §11.1 */
    if (await entryHash(prev, payload) !== e.hash) {
      problems.push(`audit entry seq ${e.seq}: contents do not match its hash`);
    }
  }
  if (redactions) {
    say("note", `redactions: ${redactions} entr${redactions === 1 ? "y" : "ies"} erased under a retention or erasure request. Their position and hash are still proven; their content no longer exists to check.`);
  }

  /* §11.3 order, and §11.1 session links. */
  for (let i = 1; i < entries.length; i++) {
    if (!(Number.isInteger(entries[i].seq) && Number.isInteger(entries[i - 1].seq) && entries[i].seq > entries[i - 1].seq)) {
      problems.push(`order: entries are not in sequence order (seq ${entries[i].seq} comes after a later or equal one)`);
      break;
    }
  }
  const subjectId = String((pack.subject && pack.subject.id) || "");
  const session = [];
  for (const e of entries) {
    const derived = e.redacted ? "" : scopeOf(e.detail);
    const carried = String(e.scope || "");
    if (derived && carried && derived !== carried) problems.push(`audit entry seq ${e.seq}: says it belongs to ${carried} but its own contents name ${derived}`);
    if (subjectId && (derived || carried) === subjectId) session.push(e);
  }
  let last = null, linked = 0;
  for (const e of session) {
    if (e.scopePrev) {
      linked++;
      if (e.scopePrev !== (last ? last.hash : GENESIS)) {
        problems.push(`session: entry seq ${e.seq} follows an entry of this session that is not in this pack — an entry has been removed from the middle of the record`);
      }
    }
    last = e;
  }
  if (session.length) {
    if (linked === session.length) say("pass", `session: all ${linked} entries of ${subjectId} link to the one before — none is missing from between them`);
    else if (linked) say("note", `session: ${linked} of ${session.length} entries carry a session link; the earlier ones predate it`);
    else say("note", "session: no entry carries a session link (written before format 4) — an entry removed from the middle would not be detected");
  }

  /* Origin. */
  const ed = (manifest.signatures || []).find((s) => s.alg === "ed25519");
  let pub = null;
  if (ed) {
    pub = Uint8Array.from(atob(ed.publicKey), (c) => c.charCodeAt(0));
    if (publicKey) {
      const pinned = publicKey.split(",").map((k) => k.trim()).filter(Boolean)
        .map((k) => hex(Uint8Array.from(atob(k), (c) => c.charCodeAt(0))));
      if (pinned.includes(hex(pub))) say("pass", `origin: verified against the pinned key (${ed.keyId})`);
      else problems.push(`origin: the bundle's key ${ed.keyId} is not one of the keys you pinned`);
    } else {
      say("note", `origin: key ${ed.keyId} (${ed.origin}) — shown, not verified. Obtain the issuer's key from GET /v1/keys and paste it above to check origin.`);
    }
    const body = enc.encode(canonical(manifest.files));
    const okSig = await ed25519Verify(pub, body, Uint8Array.from(atob(ed.signature), (c) => c.charCodeAt(0)));
    if (okSig === null) say("note", "manifest: this browser has no Ed25519, so signatures are shown but not checked");
    else if (okSig) say("pass", "manifest: signature verified");
    else problems.push("manifest: signature does not verify — this bundle was not assembled by the holder of that key");
  } else if (publicKey) {
    problems.push("origin: no Ed25519 manifest signature, and one is required (a key is pinned)");
  }

  /* The checkpoint, the proofs, and the witness. */
  let witnessSatisfied = false;
  if (files["checkpoint"]) {
    const cp = parseNote(text("checkpoint"));
    const logSig = cp.signatures.find((s) => s.name === cp.origin);
    if (pub && logSig) {
      const okCp = await ed25519Verify(pub, enc.encode(cp.body), logSig.sig);
      if (okCp) say("pass", `checkpoint: signature verified (size ${cp.size})`);
      else if (okCp === false) problems.push("checkpoint: signature does not verify under the bundle's key");
    }
    if (hex(cp.root) !== pack.merkle.root || cp.size !== pack.merkle.size) {
      problems.push("checkpoint: does not match the tree the pack describes");
    }

    const cosigs = cp.signatures.filter((s) => s.name !== cp.origin && s.sig.length === 72);
    const wKeys = witnessKey.split(",").map((k) => k.trim()).filter(Boolean);
    for (const wk of wKeys) {
      const wpub = Uint8Array.from(atob(wk), (c) => c.charCodeAt(0));
      let found = false;
      for (const c of cosigs) {
        const want = hex(await sha256(concat(enc.encode(c.name), new Uint8Array([0x0a, 0x04]), wpub))).slice(0, 8);
        const t = Number(new DataView(c.sig.buffer, c.sig.byteOffset, 8).getBigUint64(0));
        const msg = concat(enc.encode(`cosignature/v1\ntime ${t}\n`), enc.encode(cp.body));
        if (c.keyHash === want && (await ed25519Verify(wpub, msg, c.sig.subarray(8)))) { found = true; break; }
      }
      if (found) { witnessSatisfied = true; say("pass", `witness: a pinned key cosigned this checkpoint — the history up to size ${cp.size} is the one it saw`); }
    }
    if (!cosigs.length && !wKeys.length) {
      say("note", "witness: none — completeness rests on the log alone; a witness cosignature is what would show this history is the one a second party saw");
    } else if (cosigs.length && !wKeys.length) {
      say("note", `witness: cosigned by ${cosigs.map((c) => c.name).join(", ")} — paste a witness key above to check it`);
    }

    /* §10.2 / §10.3 */
    const wit = (pack.merkle && typeof pack.merkle.witnessed === "object" && pack.merkle.witnessed) || {};
    if (wit.supersededBySeal) {
      say("note", `witness: NOT CHECKED — the witnessed size (${wit.size}) is beyond this tree. The log says it was sealed at size ${wit.supersededBySeal.size}, but a seal entry is an ordinary log entry and this pack cannot tell a lawful seal from a shortened history.`);
    } else if (wit.consistencyError) {
      problems.push(`witness: ${wit.consistencyError}`);
    } else if (wit.consistency) {
      const con = wit.consistency;
      let noteOk = false, why = "no cosigned note shipped with the proof";
      if (wit.cosignedNote) {
        try {
          const wcp = parseNote(wit.cosignedNote);
          if (wcp.size !== con.oldSize || hex(wcp.root) !== con.oldRoot) {
            why = `the cosigned note is for a different tree than the proof claims (note: size ${wcp.size}; proof: size ${con.oldSize})`;
          } else if (wKeys.length) {
            for (const wk of wKeys) {
              const wpub = Uint8Array.from(atob(wk), (c) => c.charCodeAt(0));
              for (const c of wcp.signatures.filter((s) => s.sig.length === 72)) {
                const want = hex(await sha256(concat(enc.encode(c.name), new Uint8Array([0x0a, 0x04]), wpub))).slice(0, 8);
                const t = Number(new DataView(c.sig.buffer, c.sig.byteOffset, 8).getBigUint64(0));
                const msg = concat(enc.encode(`cosignature/v1\ntime ${t}\n`), enc.encode(wcp.body));
                if (c.keyHash === want && (await ed25519Verify(wpub, msg, c.sig.subarray(8)))) { noteOk = true; break; }
              }
              if (noteOk) break;
            }
            if (!noteOk) why = "no pinned witness key verifies the cosignature on that earlier size";
          } else {
            why = "no witness key pinned, so the cosignature on that size is shown, not verified";
          }
        } catch (e) { why = `the cosigned note could not be read (${e.message})`; }
      }
      const okC = await verifyConsistency(con.oldSize, con.newSize, unhex(con.oldRoot), unhex(con.newRoot),
                                          con.proof.map(unhex));
      if (!okC) {
        problems.push(`witness: this tree is NOT consistent with the one cosigned at size ${con.oldSize} — entries present then are not all present now, which is what a rewritten or shortened history looks like`);
      } else if (con.newRoot !== hex(cp.root) || con.newSize !== cp.size) {
        problems.push("witness: the consistency proof is against a different tree than this bundle's checkpoint");
      } else if (noteOk) {
        witnessSatisfied = true;
        say("pass", `witness: a pinned key cosigned size ${con.oldSize} and this tree provably extends it — nothing recorded by then has been removed`);
      } else if (wKeys.length) {
        problems.push(`witness: ${why}, so the consistency proof rests on a size and root the producer chose`);
      } else {
        say("note", `witness: this tree extends a tree of size ${con.oldSize} that the pack attributes to a witness — but ${why}. Until that cosignature is verified against a key you obtained elsewhere, the earlier tree is one the producer named, so this says nothing about completeness.`);
      }
    }
    if (witnessKey && !witnessSatisfied) {
      problems.push("witness: a witness key is pinned, and nothing in this bundle carries a cosignature that key verifies");
    }

    /* Inclusion proofs. */
    let proven = 0;
    for (const e of entries) {
      if (!e.inclusionProof || e.leafIndex === null || e.leafIndex === undefined) continue;
      try {
        const got = await rootFromInclusion(e.leafIndex, cp.size, await leafHash(enc.encode(e.hash)),
                                            e.inclusionProof.map(unhex));
        if (hex(got) !== hex(cp.root)) problems.push(`audit entry seq ${e.seq}: inclusion proof does not reach the checkpoint root`);
        else proven++;
      } catch (err) {
        problems.push(`audit entry seq ${e.seq}: inclusion proof malformed (${err.message})`);
      }
    }
    say("note", `merkle: ${proven} of ${entries.length} entries proven at their positions under checkpoint size ${cp.size}`);

    /* §11.2 session heads, against this checkpoint and against the witnessed size. */
    const heads = (pack.merkle && pack.merkle.scopeHeads) || {};
    const notes = [["checkpoint", cp]];
    if (wit.consistency && wit.cosignedNote) { try { notes.push(["witnessed", parseNote(wit.cosignedNote)]); } catch (e) { /* reported above */ } }
    for (const [label, n] of notes) {
      let line;
      try { line = parseScopesLine(n.extra || []); } catch (e) { problems.push(`session heads: the ${label} note's extension line is malformed (${e.message})`); continue; }
      if (!line) {
        if (label === "checkpoint" && session.length) say("note", "session heads: this checkpoint commits to no session heads — the session's final entries could be removed without this pack showing it");
        continue;
      }
      if (!subjectId) continue;
      const sec = heads[label];
      const mine = sec && Array.isArray(sec.proofs) && !sec.error ? sec.proofs.find((x) => x && x.scope === subjectId) : null;
      if (!mine) { problems.push(`session heads: the ${label} note commits to every session's last entry, and this pack carries no proof for ${subjectId}`); continue; }
      const reaches = async (leaf) => hex(await rootFromInclusion(leaf.index, line.count,
        await leafHash(enc.encode(`underwrit-scopes\n${leaf.scope}\n${leaf.seq}\n${leaf.hash}`)), leaf.proof.map(unhex))) === hex(line.root);
      try {
        if (mine.present) {
          if (!(await reaches(mine))) { problems.push(`session heads: the ${label} proof for ${subjectId} does not reach the root the note signed`); continue; }
          const hit = session.find((e) => e.seq === mine.seq);
          if (!hit || hit.hash !== mine.hash) { problems.push(`session heads: at size ${n.size} the log committed that ${subjectId}'s last entry was seq ${mine.seq}, and this pack does not contain it. The session's final entries have been removed`); continue; }
          say("pass", `session heads: ${subjectId}'s last entry at size ${n.size} (seq ${mine.seq}) is present`);
        } else {
          const L = mine.left, R = mine.right, k = subjectId;
          const okAbs = (!L || ((await reaches(L)) && byteCmp(L.scope, k) < 0)) && (!R || ((await reaches(R)) && byteCmp(R.scope, k) > 0)) &&
            ((!L && R && R.index === 0) || (!R && L && L.index === line.count - 1) || (L && R && R.index === L.index + 1) || (!L && !R && line.count === 0));
          if (!okAbs) { problems.push(`session heads: the ${label} proof that ${subjectId} had no entries at size ${n.size} does not hold`); continue; }
          if (session.some((e) => Number.isInteger(e.leafIndex) && e.leafIndex < n.size)) { problems.push(`session heads: the log committed at size ${n.size} that ${subjectId} had no entries, and this pack shows some`); continue; }
          say("note", `session heads: ${subjectId} had no entries at size ${n.size}`);
        }
      } catch (err) { problems.push(`session heads: the ${label} proof is malformed (${err.message})`); }
    }
  } else if (format >= 2) {
    say("note", "merkle: no checkpoint in this bundle — positions not proven, chain hashes only");
  }

  if (pack.build && typeof pack.build === "object") {
    for (const [t, bad] of buildLines(pack.build)) say(bad ? "warn" : "note", `build: ${bad ? "WARNING — " : ""}${t}`);
  }

  for (const p of problems) say("fail", p);
  if (!problems.length) {
    say("pass", `OK — ${Object.keys(manifest.files || {}).length} file(s) intact, ${entries.length} audit entr${entries.length === 1 ? "y" : "ies"} verified.`);
  }
  return { ok: !problems.length, lines: out, entries: entries.length, format };
}
