---
title: "Stop Optimizing for the Demo: A Counterpoint"
author_name: "River Holloway"
author_url: "https://example.com"
created_at: "2026-04-16T11:21:00Z"
state: "live"
---

Three months on, here's what I'd add to the original.


The demo is the most dangerous artifact in software development. It
makes you optimize for "look good for ten minutes" instead of "work
correctly for ten years." And the optimizations are subtle — they
don't show up as outright lies, just as small choices accumulated
over thousands of decisions.

Build for the unhappy path. Demo the happy path if you must. Don't
let the demo dictate the architecture.


A demo asks: does the happy path work? It does not ask: does the
unhappy path? Does the long-tail of edge cases? Does the system
behave well when the network flakes, the database lags, the user
clicks the back button at exactly the wrong moment? None of those
matter at a demo. All of them matter to your users.
