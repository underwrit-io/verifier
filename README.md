# Underwrit verifier

Check an Underwrit evidence bundle yourself, without trusting Underwrit or whoever handed you the
bundle. Everything here is MIT (see LICENSE): embed it in your own audit tooling, GPLv2 included.

- `python/verify.py` is the same script every evidence bundle carries. Standard library only:
  `python3 verify.py path/to/bundle` (set `UNDERWRIT_PUBLIC_KEY` to the issuer's published key to
  check who signed it, not only that the bundle agrees with itself).
- `browser/verify.html` checks a bundle entirely in the page; nothing is uploaded. It is also
  served at https://underwrit.io/verify.html.
- `spec/evidence-format.md` and `spec/witness-protocol.md` are the formats, for writing your own.
- `python/ed25519.py`, `merkle.py`, `tsa.py` are the primitives `verify.py` embeds, as modules.

Underwrit itself (the data plane, control plane and console that produce these bundles) is a
separate, proprietary product: https://underwrit.io
