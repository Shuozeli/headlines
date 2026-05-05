# Design Patches

Append-only log of design changes that happened during implementation. Each patch corresponds to a real edit on one or more `docs/design/<doc>.md` files; this folder keeps the audit trail.

## When to add a patch

Whenever implementation surfaces a needed change in the design (a missing field, a corrected scope, a wrong invariant, a clarification), do **both**:

1. Edit the relevant `docs/design/<doc>.md` so it reflects the new decision (the design doc is always current).
2. Add a patch entry here.

Don't queue patches "for later." If the design needs a change, write the patch now — future readers should find the design doc and the patch log mutually consistent.

## File naming

`<YYYY-MM-DD>_<short-kebab-name>.md` — e.g. `2026-05-20_redaction-event-bump.md`.

If multiple patches happen on the same day, append a `-NN` suffix: `2026-05-20_a-thing-01.md`, `2026-05-20_a-thing-02.md`.

## Per-patch template

```markdown
# <one-line summary>

- **Date:** YYYY-MM-DD
- **Phase / RPC:** which phase or RPC implementation surfaced this
- **Docs updated:** `docs/design/<a>.md`, `docs/design/<b>.md`, ...

## What changed

<2–4 bullet description of the diff to the design.>

## Why

<Why the original design was wrong or insufficient, with concrete signal — failing test, contradiction with another doc, performance constraint, etc.>

## Notes

<Any follow-on work, links to commits / PRs, or future patches this implies.>
```

## Index

(none yet — this folder will fill as implementation progresses)
