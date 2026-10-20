# Base types

Ready-made types for the most common statements between people. Use them
as they are, or write your own (`myapp:gratitude`, `acme:board-post`) —
see SPEC §3.6.

| Type | Public | Private | SAID |
|---|---|---|---|
| [`dzq:gratitude`](gratitude.json) 1.2.0 — thank you | `category` | `title`, `message`, [`attachment`] | `EDM7gu9-qtygix9Ukwfo_iE9n4EGy8mU3KmMABB7hjhG` |
| [`dzq:apology`](apology.json) 1.0.0 — sorry | — | `title`, `message`, [`attachment`] | `EMA-8lnSqc0Z1oR0jazreAx3juTg5rXUdJSwHcJRIoSE` |
| [`dzq:promise`](promise.json) 1.1.0 — I will | [`until`] | `what`, [`ask`], [`payload`] | `EJ-uSUjfgcWgiUDPwNIuqBgO_U-doYgKCFYvjL_Gn0By` |

[optional]. Every type also takes `look` and `re` in its private block, and
can be addressed to one AID or to a condition.

- Every dzq reader knows these, so a file using them needs nothing else.
- None of them is special: they are type documents like yours, and
  verification treats them exactly like any other type.
- The `dzq:` source is reserved for the types in this folder. A changed
  base type is a new version with a new SAID; old statements stay valid.
- Older versions stay known: [`promise-1.0.0.json`](promise-1.0.0.json)
  (`what`, [`note`]).
- Rules beyond fields — "earned with three thank-yous", "usable until
  closed" — are not part of any type: the optional
  [promises](../extensions/promises.md) extension.

The files are written by `tools/make_types.py` from the reference
implementation and checked in CI.
