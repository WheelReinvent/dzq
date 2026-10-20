# Extension: counting — `count:` conditions (dzq/1.3)

**Status:** optional, dzq/1.3. Reference: `dzq.counting`; CLI:
`dzq presentation … --with counting`.

A condition leaf that is met by **statements the holder shows** in the same
presentation (extensions/presentation.md): "three thank-yous from me", "two
apologies from Olena", "five visits stamped by the café". Any type can be
counted — base types or your own.

## Syntax

```
count:<N>/<term>[+<term>…][@<since>]
term := <issuer> "~" <type> ("~" <field> "=" <value>)*
```

*The holder shows at least N distinct statements, each matching one of the
terms.* All terms add up to one count.

- `<N>`: 1 to 99999.
- `<issuer>`: an AID — who issued the counted statements. Required in every
  term: a condition that counted statements from anyone could be met with
  identifiers the holder makes up.
- `<type>`: a type name (`dzq:gratitude`, `myshop:visit`) or a type SAID. A
  verifier matches a name only for types it knows (base types, configured,
  or carried in the presentation's files); a SAID always.
- `<field>=<value>` (optional, repeatable): a **public** field of the
  counted statement must equal the value (strings only). Public, because
  statements are usually shown compact. The value is percent-encoded
  (UTF-8): encode white space, `%`, `,`, `/`, `+`, `~`, `=`, `@`, `(` and `)`.
- `@<since>` (optional): RFC 3339; only statements with `a.dt` at or after
  it count. `a.dt` is what each issuer stated.

A malformed `count:` leaf is never met. A verifier without this extension
treats `count:` as an unknown kind, also never met (vector
`count-without-extension`).

| Condition | Meaning |
|---|---|
| `count:3/<me>~dzq:gratitude` | three thank-yous from me, for anything |
| `count:3/<Dad>~dzq:gratitude~category=cleaned%20the%20room+<Mom>~dzq:gratitude` | three: from Dad for the room, or from Mom for anything |
| `all(any(<Marko>,<Sofia>),count:3/<Dad>~dzq:gratitude~category=room)` | Marko or Sofia, after three "room" thank-yous from Dad |
| `count:2/<Olena>~dzq:apology` | two apologies from Olena |
| `count:5/<Café>~myshop:visit@2026-10-01T00:00:00Z` | five visits since October |
| `all(<me>,count:100/<me>~dzq:gratitude~category=no%20smoking)` | to myself, 100 days without smoking |

An app's own kinds of statements (reactions, system notices) are best given
their own type (`dzenq:like`): then "thank-yous for anything" does not count
them, and they can still be counted by name.

## Evaluation

In a presentation, each `count:` leaf of a statement S's condition holds
when at least N **distinct** statements (by SAID) shown with it:

- are valid (SPEC §6) and not S itself;
- are held by the holder directly: `a.i` = holder, or an `a.dq` met through
  the holder's AID alone (no `count:` inside `count:`);
- match a term (issuer, type, fields) and `since`;
- are not issued by the holder, unless S is issued by the holder too: your
  statements to yourself count only toward your own.

## Vectors

Presentations marked `"extensions": ["counting", …]` in
`vectors/manifest.json` (with the promises extension: `promise-*`); leaves
in `vectors/conditions.json`.
