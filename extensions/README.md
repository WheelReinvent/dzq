# Extensions

Optional parts of dzq/1.0. A core gratitude never needs any of them to be
valid; an extension adds a way to prove or report something more.

| Extension | What it adds | Status |
|---|---|---|
| [letters](letters.md) | thanks to an e-mail, phone or account via one-time claim keys | dzq/1.0 |
| [periods](periods.md) | seal many gratitudes with one key event; survive rotation | dzq/1.0 |
| [redemption](redemption.md) | the issuer marks a gratitude as used | dzq/1.0 |
| [presentation](presentation.md) | prove to a verifier that you hold gratitudes, now | dzq/1.0 |
| [promises](promises.md) | `thanks:` conditions, when a promise is usable, closing early | dzq/1.2 |
| [looks](looks.md) | optional: a common look document (look/1), carried in a `.dzq` | dzq/1.2 |

## Not yet specified

Built in DzenQ on top of gratitudes, but not part of the format yet. They
need their own documents before other apps can rely on them:

- **Stamps** (categories with a picture and a weight).
- **Doors**: the verifier service and its nonce protocol.
- **Period seal inside the `.dzq` file** (an entry like `period-seal.json`),
  so a sealed gratitude can be checked offline from one file. Needs a minor
  version, since dzq/1.0 readers reject unknown entries.
