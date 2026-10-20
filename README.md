# dzq

A file format for signed statements between people — a thank-you, an
apology, a promise, or a type you define.

A `.dzq` file holds the statement, the signature and the signer's key
history. Anyone can check it offline: no server, no account, no ledger.
Signers are [KERI](https://trustoverip.github.io/tswg-keri-specification/)
identifiers, so keys can be rotated without losing the identity.

It works without infrastructure because it skips the one problem that
needs it: **dzq does not prevent double spending.** If showing the same
statement twice breaks your use case (balances, tickets, one-time coupons,
votes), you need a ledger or a registry, not dzq.

*Pronounced* dee-zik. *Started in* [DzenQ](https://github.com/WheelReinvent/DzenQ).

## Try it

```
pip install ./reference/python        # from a clone of this repo

dzq init alice && dzq init bob
dzq sign --as alice.id --type gratitude --to $(dzq whoami bob.id) \
    title="Thank you" message="For fixing my bike." category=help -o thanks.dzq
dzq verify thanks.dzq
```
```
✓ VALID
  type       dzq:gratitude
  signed by  EAcBzwG9D1bdj8ZT4Mk4GttekxbTrXGtJpI57yzaXcy_
  to         EO52ejZkESuUUafe4YEl6rFN519dPBg-d4fhoR1JNsTJ
  unchanged  yes, every byte as signed
  …
```

Change one byte in the file and it fails. `dzq hide thanks.dzq` makes a
copy without the private text that still verifies — the proof without the
words.

## Types

A type lists its fields and says which are public and which private.
dzq comes with three — `dzq:gratitude`, `dzq:apology`, `dzq:promise`
([types/](types/)) — and you can define your own:

```
dzq type new myapp:board-post --public "area*:64" --private "text*:2000" "photo@"
dzq sign --as alice.id --type myapp:board-post --to "any(<Bob>,<Dave>)" area=Podil text="Free kid's bike"
```

The type travels inside the file, so other apps can check the fields. An
app that doesn't know the type still verifies the signature.

A statement goes to one person or to a condition (`any(…)`, `all(…)`,
an e-mail or phone via a claim key). Every type can also say how it wants
to be shown (`look`) and which statement it answers (`re`).

## Under the hood

A `.dzq` is a ZIP around a signed [ACDC](https://trustoverip.github.io/tswg-acdc-specification/)
and the issuer's KERI key event log. Every part is self-addressing (named
by its Blake3 hash), so any change is detectable. Details and the
reasoning: [SPEC.md](SPEC.md), starting with §0.

## Repository

| | |
|---|---|
| [SPEC.md](SPEC.md) | the format (`dzq/1.2`, draft) |
| [types/](types/) | base types |
| [extensions/](extensions/) | optional: letters to e-mail/phone, sealing, presentations, looks; experimental promises |
| [vectors/](vectors/) | 124 test cases with expected results |
| [reference/python/](reference/python/) | reference verifier and the `dzq` CLI |
| [examples/](examples/) | a Python quickstart and a custom type |
| [docs/](docs/) | relation to KERI/ACDC; DzenQ's implementation status |
| [proposals/](proposals/) | changes under discussion |

```
python3 -m unittest discover -s reference/python/tests   # run the vectors
```

Building an implementation? Open an issue with your vector results.
Spec text CC BY 4.0, code and vectors Apache-2.0.
