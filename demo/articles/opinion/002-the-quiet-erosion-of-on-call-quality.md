---
title: "The Quiet Erosion of On-Call Quality"
author_name: "River Holloway"
author_url: "https://example.com"
created_at: "2026-04-29T01:50:00Z"
state: "live"
---

On-call rotations have been getting steadily worse, and it's not
because pager systems have gotten worse — it's because the bar for
what counts as a page has dropped.

Every metric a team adds is a potential page. Every dashboard
threshold is a future 3 AM phone call. The fixed cost of adding an
alert is roughly zero; the cumulative cost of having too many alerts
is enormous. Most teams discover this only after their good
engineers start quietly leaving.

The fix is unfashionable: ratchet *up* the bar. Treat alert volume
as a budget. If a team is paging more than once a week per oncall,
something is wrong, and the response is to delete alerts, not add
runbooks.

The good news is this is a problem with a known solution. The bad
news is that solution requires admitting that some of the alerts
your team painstakingly built are, in fact, noise.
