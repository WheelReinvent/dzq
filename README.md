# dzq

**An open file format for signed statements between people** — a
thank-you, an apology, a notice, an achievement: whatever your app needs.
One file holds the statement, the signature and everything needed to check
it. Any app can write it, any app can read it, and checking needs no server.

*dzq* is pronounced *dee-zik*. It comes from DzenQ, the first app that
uses it.

## Why it exists

Not every interaction between people is money. Banks and blockchains make
transactions unforgeable and verifiable, but most of their weight goes into
one problem: making sure nothing is spent twice. If you want a thank-you,
an apology or an official statement to be unforgeable, you usually pick
between a ledger you mostly don't need and a signing service that owns the
keys.

dzq takes the part of [KERI](https://trustoverip.github.io/tswg-keri-specification/)
that removes the central authority — a key history with the next key
committed in advance — and leaves out everything that exists only to stop
double spending.

## Is it for you?

Ask one question: **would anything break if the same statement were shown
twice — to two people, or a year later?**

- **No** — a thank-you, an apology, a post on a board, a badge, "I was
  there", a recommendation. That is dzq.
- **Yes** — a balance, a ticket, a one-time coupon, a vote. That needs a
  ledger or a registry that records "already used"; dzq has none.

A thank-you shown twice does not become two thank-yous. That is why a dzq
file needs only a signature and the signer's key history — no server, no
ledger — and is no easier to forge for it.

## Why adopt it

**Bring your own type, keep the rest.** You describe your fields — which
are public, which stay private — in a small type document. Identity,
signing, key rotation, private content, conditions, the file format and
verification come for free and are the same for everyone. Readers that
don't know your type still verify your files.

**Your users' statements stop being trapped in your app.** A dzq file
belongs to the person who received it. They can bring it into your app
from somewhere else, and take it out again.

**Verification is offline and needs no trust in anyone.** The file carries
the signer's key history. No account, no API call, no certificate
authority. If the app that issued a file disappears, the file stays
verifiable.

**Keys can change; identities don't.** Signers are
[KERI](https://trustoverip.github.io/tswg-keri-specification/) identifiers:
a lost phone means a key rotation, not a new identity, and the next key is
committed in advance, so a stolen current key cannot take the identity
over.

**You can address someone who isn't on your platform.** A statement can go
to an e-mail address, a phone number or a condition (`any(…)`, `all(…)`);
whoever proves it holds it.

**It's small and already specified.** A handful of rules, 120 test vectors
with known answers, and a reference verifier in plain Python written from
the spec alone. The vectors tell you when your implementation is done.

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
your AID: EAcBzwG9D1bdj8ZT4Mk4GttekxbTrXGtJpI57yzaXcy_

$ dzq init bob
your AID: EO52ejZkESuUUafe4YEl6rFN519dPBg-d4fhoR1JNsTJ

$ dzq types
dzq:gratitude 1.2.0   (built in)
  id       EDM7gu9-qtygix9Ukwfo_iE9n4EGy8mU3KmMABB7hjhG
  to       one AID or a condition
  public   category
  private  title, message, [attachment@]

$ dzq sign --as alice.id --type gratitude --to EO52ejZkESuUUafe4YEl6rFN519dPBg-d4fhoR1JNsTJ \
      title="Thank you" message="For fixing my bike." category=help -o thanks.dzq
wrote thanks.dzq
```

Send `thanks.dzq` any way you like. On the other side:

```
$ dzq open thanks.dzq
Statement (dzq:gratitude)
  from     EAcBzwG9D1bdj8ZT4Mk4GttekxbTrXGtJpI57yzaXcy_
  to       EO52ejZkESuUUafe4YEl6rFN519dPBg-d4fhoR1JNsTJ
  date     2026-10-19T19:21:19+00:00
  category help
  title    Thank you
  message  For fixing my bike.

(not verified yet — run: dzq verify thanks.dzq)

$ dzq verify thanks.dzq
✓ VALID
  type       dzq:gratitude
  signed by  EAcBzwG9D1bdj8ZT4Mk4GttekxbTrXGtJpI57yzaXcy_
  to         EO52ejZkESuUUafe4YEl6rFN519dPBg-d4fhoR1JNsTJ
  unchanged  yes, every byte as signed
  content    shown, and it is exactly what was signed
  final      not yet: valid as of the signer's key history in hand (event 0)
```

Change one word inside the file and verify again:

```
$ dzq verify forged.dzq
✗ NOT VALID: the content was changed after it was signed
```

### Show the proof, not the words

Bob wants to prove he got a thank-you from Alice without showing what she
wrote. He hides the private part; the copy is still the same signed
statement:

```
$ dzq hide thanks.dzq -o shown.dzq
Statement (dzq:gratitude)
  from     EAcBzwG9D1bdj8ZT4Mk4GttekxbTrXGtJpI57yzaXcy_
  to       EO52ejZkESuUUafe4YEl6rFN519dPBg-d4fhoR1JNsTJ
  date     2026-10-19T19:21:19+00:00
  category help
  private  hidden (only its digest is here: EK2t-sOOJu9iN1_iLgw1ngzjIYrKbJUpAOn02m4leqxW)

$ dzq verify shown.dzq
✓ VALID
  type       dzq:gratitude
  signed by  EAcBzwG9D1bdj8ZT4Mk4GttekxbTrXGtJpI57yzaXcy_
  to         EO52ejZkESuUUafe4YEl6rFN519dPBg-d4fhoR1JNsTJ
  unchanged  yes, every byte as signed
  content    hidden: the signature covers it, but this copy does not show it
```

Each type declares which fields stay public; for a thank-you that is the
category. Title, message and attachment travel in a salted block that only
the holder decides to reveal.

To prove to a verifier that you *hold* a statement, not just that it
exists, sign a presentation over a code the verifier gives you:
`dzq present --as bob.id --nonce CODE thanks.dzq`, checked with
`dzq presentation presentation.json --nonce CODE`.

### Your own type

A notice board wants posts to whoever lives nearby, with the area public
and the text private:

```
$ dzq type new acme:board-post --public "area*:64" --private "text*:2000" "photo@"
acme:board-post 1.0.0
  id       EK_VsOSTFf3DLBLqVXjl9CVRfCDzrS5TER39VxL0HXyN
  to       one AID or a condition
  public   area
  private  text, [photo@]

wrote types/acme-board-post-1.0.0.json

$ dzq sign --as alice.id --type acme:board-post --to "any(<Bob>,<Dave>)" \
      area=Podil text="A kid's bike, free" --attach bike.jpg -o post.dzq
```

(`*` required, `:64` at most 64 characters, `@` a file.) The type travels
inside `post.dzq`, so Bob's reader checks the fields even if it has never
heard of `acme:board-post`. A reader without the type still verifies the
signature and says the type is unknown.

Every type also gets two optional private fields: `look=<source>:<id>`
(how you'd like it shown) and `re=<SAID>` (the statement this one answers —
"thanks for the thanks").

## What a file looks like

A `.dzq` is a ZIP with `credential.acdc` inside — a signed
[ACDC](https://trustoverip.github.io/tswg-acdc-specification/) followed by
the signature and the issuer's key event log:

```json
{"v":"ACDC10JSON0001b8_","d":"EAb-LP3nFq8MK8fnRJnNt0k1vWTvUsuoii2VzW32rIS5",
 "i":"ENxefXJUbK8lY1Md19y6CammOfc05iwDBzcfvSYMFsex",          ← issuer
 "ri":"EB26KsJ7yaluWhfS4LU9KeLAMmj4JxEbu2Dih3mTvSau",
 "s":"EDM7gu9-qtygix9Ukwfo_iE9n4EGy8mU3KmMABB7hjhG",          ← type: dzq:gratitude 1.2.0
 "a":{"d":"EO0pB0efmORBFL_n0lGnF-yC78XMWGUZk8BT7YbKkx2s",
      "i":"EAlo1nISJlSdPtCf8MuEtMUB0oe02zfrKxgCsSREPGdj",     ← recipient
      "dt":"2026-10-19T12:00:00+00:00",
      "category":"help",                                      ← public field
      "c":{"d":"ENNWQRxbnL-GVVzs61Nv46W0T3fEB-1ywczWXfS5WJ7K", ← private block
           "u":"0ADuakTISDuaavVlCtHxC_87",                    ← salt
           "title":"Дякую","message":"Тип 1.2"}}}
-AABAAB…        ← Ed25519 signature
{"v":"KERI10JSON…","t":"icp",…}-AAB…    ← issuer's key history
```

(Shown wrapped and annotated; the real ACDC is one compact line.) Every `d`
is a Blake3 digest of its own content, so changing a single character
breaks it. Hiding the private block replaces it with its `d`; the
signature covers that compact form, so both copies are the same statement.

Every statement uses the same **envelope** — issuer, recipient or
condition, date, signature, key history, private block. The **type**, named
by `s` (the SAID of its type document), defines the fields. Gratitude is
the one built-in type; any app can define more, and verification does not
change.

## Status

| | |
|---|---|
| Gratitude, to an AID or a condition | `dzq/1.0` draft; used by DzenQ |
| Private content (`dzq hide`) | `dzq/1.1` draft |
| Your own types; `look` and `re` in every type | `dzq/1.2` draft |
| Statements to an e-mail or phone, sealing, presentations | [optional extensions](extensions/) |
| An app's own rules on top: promises earned with thank-yous | [experimental example](extensions/promises.md) |

## In this repository

| | |
|---|---|
| [SPEC.md](SPEC.md) | the format: envelope, types, signing, verification, the `.dzq` file |
| [extensions/](extensions/) | letters, periods (sealing), redemption, presentation, looks; experimental promises |
| [examples/](examples/) | a quickstart and example type documents |
| [schemas/](schemas/) | the built-in type document and older schemas, byte for byte, with their fixed SAIDs |
| [vectors/](vectors/) | 120 cases with expected results — pass them and you're compatible |
| [reference/python/](reference/python/) | the reference verifier |
| [conformance/rust/](conformance/rust/) | runs the vectors through DzenQ's Rust core |
| [docs/](docs/) | relation to KERI/ACDC; where DzenQ differs from the spec today |
| [proposals/](proposals/) | changes under discussion |

```
python3 -m unittest discover -s reference/python/tests
python3 tools/gen_vectors.py --check
```

Building a reader or writer? Open an issue with your vector results —
disagreements are how a spec gets precise. See [CONTRIBUTING.md](CONTRIBUTING.md).

**License:** spec text CC BY 4.0, code and vectors Apache-2.0. Implementing
the format needs no permission.
