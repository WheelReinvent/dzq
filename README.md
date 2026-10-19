# dzq

**Say something to someone — and sign it forever.**

*dzq* (say *dee-zik*) is a small file that holds one human gesture: a
thank-you today; an apology, a promise or a gift certificate tomorrow.
You write it, you sign it, you hand it over. From then on anyone can check
that it really came from you and that not a word was changed — years later,
offline, without your app, without anyone's server.

[Українською ↓](#українською)

---

## A story

Olena helped Taras move flat on a rainy Saturday. That evening Taras sends
her a thank-you:

> **Thank you for the move**
> You carried the fridge up five floors in the rain. I won't forget it.
> — Taras · 19 October 2026 · *help*

Olena gets a file, `thank-you.dzq`. It is hers now. She can keep it, show
it, or present it at a café that gives free coffee to people with three
thank-yous from neighbours.

Whoever looks at the file can check, in a second:

- ✅ it was written by **Taras** — nobody else could have signed it;
- ✅ it was written **to Olena**;
- ✅ **nothing was changed** since — not the text, not the date, not the name;
- ✅ and all of this **without asking anyone**: not Taras, not an app, not a
  server.

That's it. A gesture between two people that can't be faked and doesn't
fade.

## What can you send?

| Gesture | Example |
|---|---|
| 🙏 **Thank-you** — *works today* | "Thanks for the move." |
| 🤝 **Apology** — *planned* | "I'm sorry I missed your birthday." |
| 📜 **Promise** — *planned* | "I owe you a dinner." |
| 🎟️ **Certificate** — *planned* | "Free pizza for anyone with three thank-yous from me." |

You can also send one **to someone you don't know yet**: to an e-mail
address, a phone number, or "whoever proves X". Whoever proves it, keeps it.

## Why a file and not an app?

Because a thank-you shouldn't belong to an app. Apps close, accounts get
deleted, companies change their minds. A file you hold stays yours.

dzq is an open format: any app can write it and any app can read it.
[DzenQ](https://github.com/WheelReinvent/dzenq-landing) is the first app
that does — that's where the name comes from — but it doesn't own it.

## Check a file

```
pip install cryptography
cd reference/python
python3 -m dzq verify thank-you.dzq
```

```
VALID
  issuer     ENxefXJUbK8lY1Md19y6CammOfc05iwDBzcfvSYMFsex
  recipient  EAlo1nISJlSdPtCf8MuEtMUB0oe02zfrKxgCsSREPGdj
```

Try it on the files in [`vectors/archives/`](vectors/archives/) — some are
genuine, some are forged on purpose.

## What's inside the file

A `.dzq` file is a ZIP. Inside is one signed record, roughly:

```
from:      Taras        (his public identity)
to:        Olena        (or: "whoever proves this e-mail")
when:      2026-10-19
type:      thank-you
title:     Thank you for the move
message:   You carried the fridge up five floors…
signature: ✍️ Taras's key
+ Taras's key history, so anyone can check the signature
```

Every gesture has the same **envelope** (from, to, when, signature) around
a **type** (what is said). The thank-you is the first type; the others will
reuse the same envelope.

---

## For builders

Under the hood dzq uses open, well-studied pieces. You don't need to know
them to use a file, but here they are if you want to build one:

- the record is an [ACDC](https://trustoverip.github.io/tswg-acdc-specification/)
  credential, protected by Blake3 digests;
- identities and keys are [KERI](https://trustoverip.github.io/tswg-keri-specification/):
  people can change their keys without losing who they are;
- signatures are Ed25519.

| Where | What |
|---|---|
| [SPEC.md](SPEC.md) | the format: envelope, types, signing, checking, the `.dzq` file |
| [extensions/](extensions/) | optional parts: letters to an address, sealing, redemption, showing at a door |
| [schemas/](schemas/) | the schemas, byte for byte, with their fixed IDs |
| [vectors/](vectors/) | 64 test cases with known answers — pass them and you're compatible |
| [reference/python/](reference/python/) | a reader written from the spec alone (needs only `cryptography`) |
| [conformance/rust/](conformance/rust/) | runs the test cases through DzenQ's own core |
| [docs/](docs/) | how dzq relates to KERI/ACDC, and where DzenQ differs from the spec today |

```
python3 -m unittest discover -s reference/python/tests   # run the tests
python3 tools/gen_vectors.py --check                     # vectors match the generator
```

Building a second reader or writer? Please open an issue — disagreements
are how a spec gets precise. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Status:** `dzq/1.0`, draft. **License:** the spec text is CC BY 4.0, the
code and test files are Apache-2.0. Implementing the format needs no
permission.

---

## Українською

**Скажи щось людині — і підпиши навіки.**

*dzq* (читається «дізік») — це маленький файл з одним людським жестом:
сьогодні подякою, завтра вибаченням, обіцянкою чи подарунковим
сертифікатом. Ти пишеш, підписуєш і віддаєш. Відтоді будь-хто може
перевірити, що це справді від тебе і що жодне слово не змінено — через
роки, офлайн, без твого застосунку і без чийогось сервера.

Олена допомогла Тарасові з переїздом. Увечері Тарас надсилає їй подяку —
файл `thank-you.dzq`. Тепер він її: можна зберегти, показати, пред'явити в
кав'ярні, що пригощає людей із трьома подяками від сусідів. І кожен
переконається за секунду: написав Тарас, саме Олені, нічого не змінено — і
ні в кого не треба питати.

Формат відкритий: будь-який застосунок може писати й читати такі файли.
DzenQ — перший, звідси й назва, але не власник.

Розробникам — розділ **For builders** вище.
