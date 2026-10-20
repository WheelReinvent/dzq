# Proposal 0004: the look document (`look/1`)

**Status:** closed — implemented in dzq/1.2 as an **optional** extension (extensions/looks.md): dzq standardizes only the pointer; sources may use their own look formats · **Target:** dzq/1.2 · **Author:** DzenQ team, 2026-10-20

## Problem

Proposal 0003 lets a statement point to a look (`look: "<source>:<SAID>"`)
but leaves open what a look is. Without a common document, each app can
only draw its own looks, and a look carried inside a `.dzq` means nothing
to anyone else.

## Principles

1. **Data, not code.** A look is a small JSON description: colours,
   pictures, a font, a layout preset. No HTML, CSS, SVG or scripts — a file
   someone sent you must never run anything.
2. **A hint.** Apps map the look onto their own UI as well as they can.
   Unknown fields are ignored. A statement never becomes invalid because of
   its look.
3. **Self-addressing.** The document and every file it uses are identified
   by SAID, so they can come from anywhere and still be exactly what the
   giver chose.
4. **Small.** One card, not a design system.

## The document

```json
{
  "v": "look/1",
  "d": "<SAID of this document>",
  "name": "Gold",
  "layout": "card",
  "background": { "color": "#F4E3B5", "image": "<file SAID>", "fit": "cover" },
  "text": { "color": "#3A2A00", "font": "serif", "align": "center" },
  "accent": "#B8860B",
  "frame": { "style": "double", "color": "#B8860B" },
  "emblem": { "image": "<file SAID>", "place": "top" },
  "dark": { "background": { "color": "#2B2111" }, "text": { "color": "#F4E3B5" } }
}
```

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | `"look/1"` |
| `d` | yes | SAID of the document (computed like any SAID, `d` set to 44 `#`) |
| `name` | yes | a human name, ≤ 64 characters |
| `layout` | no | `card` (default), `letter` or `ticket` — which preset arrangement of title, message, sender, date and type fields to use |
| `background` | no | `color` (`#RRGGBB`); `image` (file SAID); `fit` = `cover` (default) or `tile` |
| `text` | no | `color`; `font` = `serif`, `sans`, `hand`, `mono` or `{ "file": "<SAID>", "family": "<name>" }`; `align` = `start`, `center` |
| `accent` | no | colour for lines, the category, the "valid until" badge |
| `frame` | no | `style` = `none`, `line`, `double`, `ornament`; `color` |
| `emblem` | no | a picture: `image` (file SAID), `place` = `top`, `corner`, `none` |
| `dark` | no | overrides for dark mode: same fields as above, any subset |

### Files

- Pictures: PNG, JPEG or WebP. Fonts: WOFF2. Nothing else.
- A file's SAID is the Blake3-256 qb64 of its bytes.
- Total of the document and its files: at most 2 MB.
- In a `.dzq` (proposal 0003), the document is `looks/<SAID>.json` and its
  files `looks/<SAID>` (no extension); the reader checks every SAID before
  use.

### Rendering rules

- The text of the statement is always readable: a renderer MAY change the
  look's text colour when its contrast with the background is too low.
- The renderer decides sizes, spacing and how the layout preset fits its
  screen. The look decides character, not pixels.
- If a file is missing or does not match its SAID, the renderer drops that
  part (a background image falls back to the background colour, a font to
  the generic family) and keeps the rest.

## What changes

- New schema: `schemas/look.schema.json` with a fixed SAID.
- Reference: `dzq look check <file>` (validate a look and its files),
  `dzq open` reports the look name.
- Vectors: a valid look; a wrong SAID; a forbidden file type; over the size
  limit; unknown fields ignored.
- DzenQ: its blanks (`gold`, `navy`, …) become look/1 documents in its
  catalogue; `look: "dzenq:<SAID>"`.

## Open questions

1. Are three layout presets (`card`, `letter`, `ticket`) the right set?
   Certificates might want their own.
2. Gradients for the background, or colour and picture only?
3. Is 2 MB the right limit for a look carried inside every custom `.dzq`?
