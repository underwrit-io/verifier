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
- `python/passport_verify.py` checks an agent passport against its issuer's published key:
  `python3 passport_verify.py <passport> --key <issuer key> [--revocations <url>]`.

Every verifier also prints the pack's build statement (spec §12): which edition and licence
produced it, and whether that was the release Underwrit signed. It warns on a modified build or an
install over its limit; `verify.py --require release` fails anything but a signed release build.

Underwrit itself (the data plane, control plane and console that produce these bundles) is a
separate, proprietary product: https://underwrit.io
