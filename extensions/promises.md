# Extension: promises — usable, closing early (dzq/1.3)

**Status:** optional, dzq/1.3. Reference: `dzq.promises`; CLI:
`dzq presentation … --with promises`.

A promise is a statement of the base type `dzq:promise` (SPEC §3.8): every
dzq verifier checks it and, without this extension, simply shows it — a
promise is a statement of intent, nothing more. This extension answers the
question a door asks: **can this holder use it now?** Earning a promise
("after three thank-yous from me") is its condition, `a.req` =
`dzq:gratitude?from=<me>&count=3` (SPEC §4); that is core.

It is **not double-spend protection** (SPEC §0). Nothing here stops a
holder from showing a promise twice; a door that must give something only
once keeps its own record.

## Usable

A promise in a valid presentation is **usable** when all hold; else
the first failing reason is reported:

| Check | Reason |
|---|---|
| `until` is absent, or later than the verifier's clock | `expired` |
| no close digest (below) in the issuer's KEL | `closed` |
| the holder meets `a.req` (SPEC §4) | `not-earned` |

The presentation is valid only if every promise in it is usable and
every other statement in it is the holder's.

There is no use counter. Showing the same promise twice is between
the holder and the issuer.

## Closing early

```
close digest(S) = SAID of {"d":"<44 #>","t":"close","g":"<promise SAID>"}
```

The issuer anchors it as a digest seal in an `ixn` event. From then on the
promise is not usable by anyone; as a signed record of what was
promised it stays valid, and a verifier reports `closed_at_sn`. Like every
KEL fact, a close is only visible to a verifier with a KEL recent enough;
doors that give real things SHOULD load the issuer's KEL fresh.

## Vectors

Presentations `promise-*`, marked `"extensions": ["promises"]`
in `vectors/manifest.json`; `close_said` in `vectors/digests.json`.
