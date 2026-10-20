# Test vectors

Files with known answers. An implementation that reproduces every expected
result in [`manifest.json`](manifest.json) and the JSON files next to it is
compatible with dzq.

| File | What |
|---|---|
| `manifest.json` | every credential, archive and presentation vector, with its inputs and expected result |
| `credentials/<name>.acdc` | a credential bundle (SPEC §5) |
| `credentials/<name>.kel` | if present: a fresher issuer KEL to verify with (SPEC §6.1) |
| `credentials/<name>.seal.json` | if present: the gratitude's period seal |
| `archives/<name>.dzq` | `.dzq` files, good and hostile |
| `presentations/<name>.json` | `dzenq-vp/1` presentations; check with the `nonce` (and `now`, if given) from the manifest |
| `types/<SAID>.json` | type documents; a vector with `"types": [...]` is checked by a reader that knows them, one without by a reader that does not |
| `conditions.json` | condition texts: does it parse, its canonical form |
| `merkle.json` | period trees: leaves, root, a proof for each leaf |
| `digests.json` | schema SAIDs, Blake3 SAIDs, redemption digests, claim-key derivations |
| `identities.json` | names of the test identifiers and their AIDs |

## Expected results

`expect` lists only the fields that matter for that vector. `valid` is
always there; `code` is the failure code of SPEC §6.4 (or `archive` when the
`.dzq` itself must be refused before verification). For archives,
`attachment` is `ok`, `mismatch`, `missing` or `null` (none named).
`type` is the type's name, or `null` when the reader does not know it
(`type_known` false).

Vectors with `"extensions": [...]` test optional extensions
([promises](../extensions/promises.md));
`"promise"` in `expect` is `usable` or the reason it is not. Skip them
unless you implement those extensions.

## Keys

All identifiers use keys derived from public seeds:
`Ed25519 seed = BLAKE3("dzq test vector key|<name>/<generation>")`. They are
test keys. Never trust them for anything.

## Regenerating

```
python3 tools/gen_vectors.py          # rewrite
python3 tools/gen_vectors.py --check  # CI: fail if the files differ from the generator
```

Output is reproducible byte for byte (fixed seeds, fixed `dt`, fixed ZIP
timestamps). Never edit a vector by hand; change the generator.
