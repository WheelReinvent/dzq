# Extension: looks (dzq/1.2)

**Status:** optional, dzq/1.2. The `look` field itself (the pointer) is
core: SPEC §3.7.

A statement may point to how it wants to be shown — a blank, colours, a
font — the way an XML document points to its stylesheet. The pointer is
`look = "<source>:<id>"` in the private block. **What a source returns is
the source's business**: an app may use its own look format. This page
defines an optional common one, look/1, for apps that want to share looks
or carry them inside a `.dzq`. Nothing else in dzq depends on it.

## Principles

1. **Data, not code.** No HTML, CSS, SVG or scripts: a file someone sent
   you must never run anything.
2. **A hint.** Apps map a look onto their own UI as well as they can;
   unknown fields are ignored; validity never depends on the look.
3. **Self-addressing.** The document and every file it uses are identified
   by SAID, so they can come from anywhere and still be exactly what the
   giver chose.
4. **Small.** One card, not a design system.

## The look/1 document

```json
{"v":"look/1","d":"<SAID>","name":"Gold","layout":"card",
 "background":{"color":"#F4E3B5","image":"<file SAID>","fit":"cover"},
 "text":{"color":"#3A2A00","font":"serif","align":"center"},
 "accent":"#B8860B","frame":{"style":"double","color":"#B8860B"},
 "emblem":{"image":"<file SAID>","place":"top"},
 "dark":{"background":{"color":"#2B2111"},"text":{"color":"#F4E3B5"}}}
```

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | `"look/1"` |
| `d` | yes | SAID of the document: Blake3-256 qb64 of its compact JSON with `d` = 44 `#` |
| `name` | yes | a human name, ≤ 64 characters |
| `layout` | no | `card` (default), `letter`, `ticket` |
| `background` | no | `color` (`#RRGGBB`), `image` (file SAID), `fit` = `cover` (default) or `tile` |
| `text` | no | `color`; `font` = `serif`, `sans`, `hand`, `mono`, or `{"file": "<SAID>", "family": "<name>"}`; `align` = `start` or `center` |
| `accent` | no | colour for lines, the category, the "until" badge |
| `frame` | no | `style` = `none`, `line`, `double`, `ornament`; `color` |
| `emblem` | no | `image` (file SAID), `place` = `top`, `corner`, `none` |
| `dark` | no | overrides for dark mode: any of the fields above |

Schema: [schemas/look.schema.json](../schemas/look.schema.json).

### Files

- Pictures: PNG, JPEG or WebP. Fonts: WOFF2. Nothing else.
- A file's SAID is the Blake3-256 qb64 of its bytes.
- The document and its files together: at most 2 MB.

### Rendering

- The statement's text stays readable: a renderer MAY change the text
  colour when its contrast with the background is too low.
- The renderer decides sizes and spacing; the look decides character, not
  pixels.
- A missing file, or one that does not match its SAID, drops that part only
  (an image falls back to the colour, a font to its generic family).

## In a `.dzq` file

A `.dzq` MAY carry the look the statement names, if it is a look/1
document: `looks/<SAID>.json` (the document) and `looks/<SAID>` (each file,
no extension). Never required.
Givers carry their own, custom looks and leave out catalogue looks every
app already has. Compact copies made for showing never carry a look.

A reader reports the look as one of:

| Result | Meaning |
|---|---|
| none | the statement names no look (or its content is hidden) |
| `named` | named, but not carried: ask the source |
| `ok` | carried, the document and its files check out |
| `invalid: …` | carried but wrong (SAID mismatch, forbidden file type, too large): ignore it |

## Vectors

Credentials `look-*`; archives `look-carried`, `look-named-only`,
`look-document-tampered`, `look-forbidden-file`.
