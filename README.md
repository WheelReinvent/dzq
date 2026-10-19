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

## Try it in a terminal

No code needed. Install the reference tool from this repository:

```
git clone https://github.com/WheelReinvent/dzq && cd dzq
pip install ./reference/python
```

Create two identities, sign a statement, open it, verify it:

```
$ dzq init alice
created alice.id  (private: it holds your signing secret)
your AID: EGZXbjjIy4uuw8A15dsEjpEbFeXcfaCvbuhEuhBZN_IT

$ dzq init bob
your AID: EBeMyZxeujKT2HeRoSxmbf7JdNpEY2G3gT6kwFtz8E8k

$ dzq types
gratitude
  fields:   title, message, category
  optional: attachment (use --attach for a file)

$ dzq sign --as alice.id --type gratitude --to EBeMyZxeujKT2HeRoSxmbf7JdNpEY2G3gT6kwFtz8E8k \
      title="Thank you" message="For fixing my bike." category=help -o thanks.dzq
wrote thanks.dzq
```

Send `thanks.dzq` any way you like. On the other side:

```
$ dzq open thanks.dzq
Statement (gratitude)
  from     EGZXbjjIy4uuw8A15dsEjpEbFeXcfaCvbuhEuhBZN_IT
  to       EBeMyZxeujKT2HeRoSxmbf7JdNpEY2G3gT6kwFtz8E8k
  date     2026-10-19T18:57:17+00:00
  title    Thank you
  message  For fixing my bike.
  category help

(not verified yet — run: dzq verify thanks.dzq)

$ dzq verify thanks.dzq
✓ VALID
  signed by  EGZXbjjIy4uuw8A15dsEjpEbFeXcfaCvbuhEuhBZN_IT
  to         EBeMyZxeujKT2HeRoSxmbf7JdNpEY2G3gT6kwFtz8E8k
  unchanged  yes, every byte as signed
  final      not yet: valid as of the signer's key history in hand (event 0)
```

Change one word inside the file and verify again:

```
$ dzq verify forged.dzq
✗ NOT VALID: the content was changed after it was signed
```

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
