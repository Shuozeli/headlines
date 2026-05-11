---
title: "In Defense of the Long Comment: A Followup"
author_name: "Jamie Quill"
author_url: "https://example.com"
created_at: "2026-04-24T14:10:00Z"
state: "live"
---

**A note up front:** this piece extends an earlier post on the same topic with new examples.


There's a school of thought in software engineering that holds: "good
code doesn't need comments." It's a popular dictum and a deeply wrong
one.

Write the code. Then ask, "what would I want a teammate to know
about this in six months that isn't visible in the syntax?" Then
write that down.


The "no comments" dogma comes from a real frustration: the comment
that just restates the next line of code. Those *are* useless. But
the existence of bad comments doesn't argue against good ones any
more than the existence of bad code argues against code itself.

Code, even good code, communicates **what** is happening. Comments
communicate **why**. A function called `compute_dwell_time` is a
self-documenting name. A comment above it that says "Dwell time is
clamped at 24 hours because the events service rejects values larger
than that, see ADR-014" is information you cannot derive from any
amount of clever naming.
