# Extensions

Optional parts of dzq. A core statement never needs any of them to be
valid; an extension adds a way to prove or report something more.

| Extension | What it adds | Status |
|---|---|---|
| [letters](letters.md) | statements to an e-mail, phone or account via one-time claim keys | dzq/1.0 |
| [periods](periods.md) | seal many statements with one key event; survive rotation | dzq/1.0 |
| [redemption](redemption.md) | the issuer *hints* that it considers a statement used (not double-spend protection: SPEC §0) | dzq/1.0 |
| [presentation](presentation.md) | prove to a verifier that you hold statements, now | dzq/1.0 |
| [looks](looks.md) | a common look document (look/1), carried in a `.dzq` | optional, dzq/1.2 |
| [promises](promises.md) | when a promise is usable; closing it early | optional, dzq/1.3 |

## Not yet specified

Built in DzenQ on top of gratitudes, but not part of the format yet:

- **Stamps** (categories with a picture and a weight).
- **Doors**: the verifier service and its nonce protocol.
- **Period seal inside the `.dzq` file** (an entry like `period-seal.json`),
  so a sealed statement can be checked offline from one file. Needs a minor
  version, since readers reject unknown entries.
