# Base types

Ready-made types for the most common statements between people. Use them
as they are, or write your own (`myapp:gratitude`, `acme:board-post`) —
see SPEC §3.6.

| Type | Public | Private | SAID |
|---|---|---|---|
| [`dzq:gratitude`](gratitude.json) 1.2.0 — thank you | `category` | `title`, `message`, [`attachment`] | `EA7UscxbMPT20L2iL0_rh1kyV_atIttXW3erkpAKqsHy` |
| [`dzq:apology`](apology.json) 1.0.0 — sorry | — | `title`, `message`, [`attachment`] | `EPAEJEeoWrF34_fWkqnTSHlhUPddcHsAYrPKBDhdULzi` |
| [`dzq:promise`](promise.json) 1.1.0 — I will | [`until`] | `what`, [`ask`], [`payload`] | `ENdXpl_T_qnJbaY59IOIHOtlAUyqo3gd6G4VhH_P8TCo` |

[optional]. Every type also takes `look` and `re` in its private block, and
can be addressed to one AID or to a condition.

- Every dzq reader knows these, so a file using them needs nothing else.
- None of them is special: they are type documents like yours, and
  verification treats them exactly like any other type.
- The `dzq:` source is reserved for the types in this folder. A changed
  base type is a new version with a new SAID; old statements stay valid.
- Rules beyond fields — "earned with three thank-yous", "usable until
  closed" — are not part of any type: earning is the statement's condition
  (`"req": "dzq:gratitude?from=<me>&count=3"`, SPEC §4); usable and closing
  early are the optional [promises](../extensions/promises.md) extension.

The files are written by `tools/make_types.py` from the reference
implementation and checked in CI.
