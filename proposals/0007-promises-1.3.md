# Proposal 0007: conditions and promises for "thank now, repay later"

**Status:** closed — implemented in dzq/1.3 · **Author:** DzenQ team, 2026-10-20

Raised while moving DzenQ certificates to `dzq:promise`: a reward must be
earnable with thank-yous — from several people, for different things or
for anything — and carry something of value.

Outcome:

- **`a.req` replaces `a.dq`** (envelope names are short, like `i`, `dt`).
  It is one condition or a list of them, any one of which is enough.
- **A condition reads like a URL**, one field one value:
  - `?aid=<AID>` — the holder is this AID;
  - `?claim=<key>` — the holder has this claim key (letters);
  - `<type>?from=<AID>&<field>=<value>&to=…&since=…&count=N` — the holder
    shows at least N such statements of any type: thank-yous, apologies,
    an app's own types.
  `from`, `to`, `since`, `count` are reserved. Each condition counts on its
  own. `any(…)`, `all(…)`, `claim:`, `count:` and `thanks:` are gone.
- **A category belongs to its issuer**, so it is asked for together with
  `from`.
- **`dzq:promise`**: `what`, optional `ask` (how to earn it), optional
  `payload` (a code, an invite: private, not encrypted).
- **Promises extension** (optional): usable (until, closed early).

Considered and rejected on the way: a query language inside one string
(`count:3/…~…`, `min(…)`, search syntax with `OR` and brackets), JSONPath
(an engine in every verifier, filters on hidden fields), earning moved out
of the format into apps (loses "thank now, repay later"), sums across
conditions (each condition counts on its own).
