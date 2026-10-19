# dzq-verify — reference verifier for dzq/1.0

Checks `.dzq` files, credential bundles and presentations exactly as
[SPEC.md](../../SPEC.md) says, with no DzenQ code and no network.

- Pure Python, one dependency: `cryptography` (Ed25519).
- Includes BLAKE3 (checked against the official C implementation), the CESR
  primitives a gratitude uses, and a KERI 1.0 key event log verifier
  (`icp`/`rot`/`ixn`, pre-rotation, abandonment; checked against keripy
  events).
- Written to be read, not to be fast.

```
pip install -e .            # or just: pip install cryptography
dzq verify thanks.dzq
dzq verify bundle.acdc --kel fresh.kel --seal seal.json --json
dzq presentation vp.json --nonce CODE
```

Exit code 0 = valid, 1 = invalid, 2 = could not read the input.

| Module | Spec |
|---|---|
| `blake3.py` | BLAKE3 hash and derive_key |
| `cesr.py` | qb64 primitives, `-A##` signature groups, attachment skipping |
| `kel.py` | KERI KEL verification (SPEC §6.2 step 5) |
| `acdc.py` | canonical form, SAIDs, schemas (SPEC §3) |
| `dq.py` | conditions (SPEC §4) |
| `verify.py` | credential verification (SPEC §6), claims, presentations |
| `merkle.py` | period trees (extensions/periods.md) |
| `archive.py` | `.dzq` reading and writing (SPEC §7) |
| `identity.py` | `Identity`: create an identifier, `thank(...)` → signed `.dzq` bytes |
| `build.py` | issuing side underneath, also used to make the test vectors |

Not supported (reported, never silently accepted): delegated identifiers,
witnessed KELs, weighted thresholds, pre-1.0 legacy credentials.
