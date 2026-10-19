# dzq

**An open file format for signed statements between people** — thank-yous
today, apologies, promises and certificates next. One file holds the
statement, the signature and everything needed to check it. Any app can
write it, any app can read it, and checking needs no server.

*dzq* is pronounced *dee-zik*. It comes from DzenQ, the first app that uses
it; DzenQ does not own it.

## Why adopt it

**Your users' thank-yous stop being trapped in your app.** Kudos, badges,
endorsements, "thanks" reactions — every platform has them, and every
platform keeps them. A dzq file belongs to the person who received it. They
can bring it into your app from somewhere else, and take it out again. That
is a reason for them to trust your app, not a reason to leave it.

**Verification is offline and needs no trust in anyone.** The file carries
the signer's public key history. A verifier checks the signature, the
content and the key history locally: no account, no API call, no
certificate authority, no DzenQ server. If DzenQ disappears tomorrow, every
file issued by anyone stays verifiable.

**Keys can change; identities don't.** Signers are
[KERI](https://trustoverip.github.io/tswg-keri-specification/) identifiers:
a lost phone or a new device means a key rotation, not a new identity, and
the next key is committed in advance, so a stolen current key cannot take
the identity over. Statements made before a rotation can be sealed so they
stay valid after it.

**You can address someone who isn't on your platform.** A statement can go
to an e-mail address, a phone number or a condition (`any(…)`, `all(…)`);
whoever proves it holds it — again without a server vouching for anyone.

**It's small and already specified.** One credential type, a handful of
rules, 64 test vectors with known answers, and a reference verifier of about
a thousand lines of Python that was written from the spec alone. A second
implementation is an afternoon's job, and the vectors tell you when you're
done.

## The whole flow

```python
import dzq

alice = dzq.Identity.create()
bob = dzq.Identity.create()

# Sign: a type, a recipient, the type's fields
statement = alice.sign(
    type="gratitude",
    to=bob.aid,
    content={"title": "Thank you", "message": "For fixing my bike.", "category": "help"},
)

data = statement.to_dzq()          # bytes of a .dzq file — send them any way you like

received = dzq.open(data)          # what it says; trusts nothing yet
print(received)
```
```
Statement (gratitude)
  from     EJ4Vy38rSIBGnBHaX6iFdbIBMHhP51hR5WhEthMXChP1
  to       EGlc_eGY8l1r-YriAbPKIT3a5YZWhENrrXoeGO8EEg92
  date     2026-10-19T18:49:35+00:00
  title    Thank you
  message  For fixing my bike.
  category help
```
```python
print(received.verify())           # whether to believe it
```
```
✓ VALID
  signed by  EJ4Vy38rSIBGnBHaX6iFdbIBMHhP51hR5WhEthMXChP1
  to         EGlc_eGY8l1r-YriAbPKIT3a5YZWhENrrXoeGO8EEg92
  unchanged  yes, every byte as signed
  final      not yet: valid as of the signer's key history in hand (event 0)
```

Change one word inside and `verify()` says
`✗ NOT VALID: the content was changed after it was signed`.

`dzq.types.TYPES` lists the types and their fields; today that is
`gratitude` (title, message, category, optional attachment). `to` can also
be a condition such as `"any(<AID>,<AID>)"`. Runnable, step by step:
[examples/quickstart.py](examples/quickstart.py).

## What a file looks like

A `.dzq` is a ZIP with `credential.acdc` inside — a signed
[ACDC](https://trustoverip.github.io/tswg-acdc-specification/) followed by
the signature and the issuer's key event log:

```json
{"v":"ACDC10JSON0001d2_","d":"EM_xnTusP2_H3_i9dPKAtZjMp_T1Oipj6FGMhPaqZ7Rf",
 "i":"ENxefXJUbK8lY1Md19y6CammOfc05iwDBzcfvSYMFsex",          ← issuer
 "ri":"EB26KsJ7yaluWhfS4LU9KeLAMmj4JxEbu2Dih3mTvSau",
 "s":"EHJJvD_pHa1kHRWiQq9o1KxNHNpnFpArKmGGltmDjTav",          ← type: gratitude 1.0.0
 "a":{"d":"EF6u4LOVhQUvqeIRnPWyC_PAJz6d7W2J1u7WXI8sCmcH",
      "i":"EAlo1nISJlSdPtCf8MuEtMUB0oe02zfrKxgCsSREPGdj",     ← recipient
      "dt":"2026-10-19T12:00:00+00:00",
      "title":"Дякую","message":"За допомогу з переїздом","category":"help"}}
-AABAAB…        ← Ed25519 signature
{"v":"KERI10JSON…","t":"icp",…}-AAB…    ← issuer's key history
```

(Shown wrapped and annotated; the real ACDC is one compact line.) Every `d`
is a Blake3 digest of its own content, so changing a single character
breaks it.

Every statement uses the same **envelope** — issuer, recipient or
condition, date, signature, key history. The **type**, named by `s`, defines
the content fields. Gratitude is the first type; new types are new schemas
in the same envelope, and verification does not change.

## From the command line

```
pip install cryptography
cd reference/python
python3 -m dzq verify ../../vectors/archives/minimal.dzq
```

The answer is honest about freshness: a statement that isn't sealed is
"valid as of the key history you have"; pass a fresher one with `--kel`.

## Status and roadmap

| | |
|---|---|
| ✅ Gratitude (to an AID or a condition) | `dzq/1.0` draft, implemented in DzenQ |
| ✅ Letters to an e-mail / phone, sealing, redemption, holder-bound presentation | optional extensions |
| 🔜 Selective disclosure (hide the text, keep the signature checkable) | before a public pilot |
| 🔜 Apology, promise, certificate | new types |

## In this repository

| | |
|---|---|
| [SPEC.md](SPEC.md) | the format: envelope, types, signing, verification, the `.dzq` file |
| [extensions/](extensions/) | letters, periods (sealing), redemption, presentation |
| [schemas/](schemas/) | the schemas, byte for byte, with their fixed SAIDs |
| [vectors/](vectors/) | 64 cases with expected results — pass them and you're compatible |
| [reference/python/](reference/python/) | the reference verifier |
| [conformance/rust/](conformance/rust/) | runs the vectors through DzenQ's Rust core |
| [docs/](docs/) | relation to KERI/ACDC; where DzenQ differs from the spec today |

```
python3 -m unittest discover -s reference/python/tests
python3 tools/gen_vectors.py --check
```

Building a reader or writer? Open an issue with your vector results —
disagreements are how a spec gets precise. See [CONTRIBUTING.md](CONTRIBUTING.md).

**License:** spec text CC BY 4.0, code and vectors Apache-2.0. Implementing
the format needs no permission.
