# Proposal 0007: promises that DzenQ certificates fit into

**Status:** closed — implemented in dzq/1.3 · **Author:** DzenQ team, 2026-10-20

Raised while moving DzenQ certificates to `dzq:promise`:

1. **Thank-yous from different people for different things add up.**
   `thanks:` now takes terms `<issuer>:<category>` joined with `+`, all
   counting toward one N: `thanks:3/<Dad>:room+<Mom>:*`.
2. **"For anything".** `*` matches any *general* category. App categories
   (`dzenq:like`, SPEC §8.3) are not matched, so an app's reactions and
   system thank-yous do not inflate "for anything"; they can still be named.
3. **Something of value inside.** `dzq:promise` 1.1.0: `what`, optional
   `ask` (how to earn it), optional `payload` (a code, an invite link).
   `payload` is private, not encrypted: the holder sees it at once. What
   must arrive only after earning is sent then, as its own statement.
4. **Earning is something other apps can rely on.** The promises extension
   is optional instead of experimental.

`dzq:promise` 1.0.0 stays valid. The old `thanks:<N>/<category>/<issuers>`
form was never part of a published version and is not kept.
