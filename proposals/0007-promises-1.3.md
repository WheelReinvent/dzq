# Proposal 0007: promises that DzenQ certificates fit into

**Status:** closed — implemented in dzq/1.3 · **Author:** DzenQ team, 2026-10-20

Raised while moving DzenQ certificates to `dzq:promise`:

1. **Statements from different people, for different things, add up.**
2. **"For anything"** from a person.
3. **Something of value inside** the promise.
4. **Earning is something other apps can rely on**, not experimental.

Outcome:

- `dzq:promise` 1.1.0: `what`, optional `ask` (how to earn it), optional
  `payload` (a code, an invite link). `payload` is private, not encrypted:
  the holder sees it at once. What must arrive only after earning is sent
  then, as its own statement.
- A general **`count:`** condition instead of a gratitude-only one: count
  statements of **any type**, from given issuers, optionally with given
  public field values; terms add up to one N:
  `count:3/<Dad>~dzq:gratitude~category=room+<Mom>~dzq:gratitude`.
  "For anything" = no field filter. An app's own kinds (likes) are their
  own type, so they are not counted unless named.
- Two optional extensions: [counting](../extensions/counting.md) and
  [promises](../extensions/promises.md) (usable, closing early).

No earlier promise version or `thanks:` form is kept: neither was issued.
