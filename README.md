# dzq — signed gestures between people

**dzq** (pronounced *dee-zik*) is a file format for a signed gesture from one
person to another — a thank-you today; an apology, a promise or a
certificate later. Anyone can check the file, offline, with no account and
no server.

Every dzq file is an **envelope** (who, to whom, when, signature, key
history — the same for every gesture) around a **type** (what is said). The
first type is **gratitude**.

This repository is the format: the specification, its schemas, test
vectors, and a reference verifier that has nothing to do with any app.
[DzenQ](https://github.com/WheelReinvent/dzenq-landing) is the first
application that writes and reads it. Others are welcome to.

**Status:** `dzq/1.0`, draft 1 (2026-10-19).

## What is in here

| Path | What |
|---|---|
| [SPEC.md](SPEC.md) | the core: credential, conditions, bundle, verification, `.dzq` file |
| [extensions/](extensions/) | optional parts: letters (claim keys), periods, redemption, presentation |
| [schemas/](schemas/) | the JSON schemas, byte for byte, with their SAIDs in [index.json](schemas/index.json) |
| [vectors/](vectors/) | 64 cases (credentials, .dzq files, presentations) with expected results, plus conditions, Merkle and digest tables |
| [reference/python/](reference/python/) | reference verifier: Python 3.9+, needs only `cryptography` (for Ed25519); BLAKE3, CESR and KERI log checking included |
| [conformance/rust/](conformance/rust/) | runs the vectors through the DzenQ core |
| [docs/keri-acdc-alignment.md](docs/keri-acdc-alignment.md) | where dzq/1.0 differs from plain KERI/ACDC, and why |
| [docs/dzenq-implementation.md](docs/dzenq-implementation.md) | where DzenQ today differs from the spec |
| [tools/gen_vectors.py](tools/gen_vectors.py) | makes the vectors |

## In one minute

- A gratitude is an [ACDC](https://trustoverip.github.io/tswg-acdc-specification/)
  credential: issuer, recipient (or a condition), date, title, message,
  category, optional attached file — all covered by Blake3 SAIDs.
- It is signed by the issuer's [KERI](https://trustoverip.github.io/tswg-keri-specification/)
  identifier. The file carries the issuer's key event log, so the signature
  can be checked without asking anyone.
- A `.dzq` file is a ZIP with `credential.acdc` in it (and, optionally, the
  attached file and display metadata).
- Valid at once; after a key rotation, only gratitudes the issuer *sealed*
  before it stay valid. A verifier says whether its answer is final
  (`sealed`) or only true as of the key log it had.

## Check a file

```
pip install cryptography
cd reference/python
python3 -m dzq verify path/to/thanks.dzq
python3 -m dzq verify bundle.acdc --kel fresh-issuer.kel --seal seal.json
python3 -m dzq presentation vp.json --nonce THE-CODE-YOU-GAVE
```

As a library:

```python
from dzq import check_dzq
result = check_dzq(open("thanks.dzq", "rb").read())
result.valid, result.sealed, result.recipient, result.code
```

## Run the tests

```
python3 -m unittest discover -s reference/python/tests
python3 tools/gen_vectors.py --check
```

The tests also check the KERI log verifier against events signed by
[keripy](https://github.com/WebOfTrust/keripy), so the reference is checked
against another implementation, not only against itself.

## Contributing

Issues and pull requests are welcome, especially from people building a
second reader. Changes to anything that decides validity need a new vector.
See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Specification text: CC BY 4.0 ([LICENSE-SPEC](LICENSE-SPEC)). Code, schemas,
vectors: Apache-2.0 ([LICENSE](LICENSE)). Implementing the format needs no
permission.

---

## Коротко українською

dzq (читається «дізік») — формат підписаних жестів між людьми: сьогодні
подяка, згодом вибачення, обіцянка, сертифікат. Кожен файл — це конверт
(хто, кому, коли, підпис, журнал ключів — однаковий для всіх жестів) і тип
(що саме сказано). Перший тип — подяка. Тут описано, що у файлі, як його
підписати й перевірити, тож будь-який застосунок може видавати й читати
такі файли. DzenQ — перший, хто це робить, а не власник формату.

- `SPEC.md` — ядро формату dzq/1.0; `extensions/` — необов'язкові частини
  (листи на адресу, періоди-печатки, погашення, пред'явлення).
- `schemas/` — схеми з постійними SAID, `vectors/` — тестові файли з
  відповідями, `reference/python/` — незалежний перевіряльник.
- `docs/dzenq-implementation.md` — де DzenQ зараз відрізняється від
  специфікації й що варто змінити.
