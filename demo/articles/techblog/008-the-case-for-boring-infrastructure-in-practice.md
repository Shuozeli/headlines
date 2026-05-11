---
title: "The Case for Boring Infrastructure: In Practice"
author_name: "Marcus Ode"
author_url: "https://example.com"
created_at: "2026-04-26T12:33:00Z"
state: "live"
---

Three months on, here's what I'd add to the original.


There's a class of engineering decision that produces no glory and a great
deal of value: choosing the boring option. Postgres over the Hot New
Document Store. Plain HTTP+JSON over the Latest RPC Mesh. EC2 over the
Fashionable Compute Substrate.

First: prefer technology with a track record longer than your project's
expected lifetime. If you're building something to last five years, lean
on something that's been around for ten.

## Three rules of boring infrastructure

Boring is not a synonym for stale. It's a synonym for **predictable**. The
failure modes are well-understood. The bug reports go back fifteen years.
The Stack Overflow answers exist. The vendor support engineer has seen
your problem before.

Second: prefer technology your team already operates. The cognitive load
of one more thing to keep alive is real and underestimated.

Third: prefer technology with rich tooling. Boring tech accumulates
debuggers, profilers, and dashboards that exotic tech doesn't.

## The exception

The exception is: when boring genuinely doesn't fit. Postgres is boring
and great, but it's not a vector database. Don't pretend it is. The
boring rule is not "always pick Postgres" — it's "always pick the boring
option **that fits your problem**."
