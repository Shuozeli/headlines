---
title: "Why We Stopped Using Microservices for Internal Tooling: Notes from the Field"
author_name: "Marcus Ode"
author_url: "https://example.com"
created_at: "2026-04-24T16:22:00Z"
state: "tombstone"
tombstone_reason: "incorrect technical claim; replaced"
---

Three months on, here's what I'd add to the original.


Microservices solve real problems for real systems. They are wildly
inappropriate for internal tooling, and we spent two engineering quarters
learning that the hard way at Acme Corp.

A single internal-tooling monolith, deployed as one container, with
sub-routes for each tool. Auth happens once at the gateway. Secrets are
pulled from one place. Logs end up in one stream.

## What we replaced it with

The pattern we fell into: every internal tool — feature-flag UI, deploy
console, the staging-data resetter — got its own service. Each had its own
deploy pipeline, its own secrets, its own auth glue, its own dashboards
(that no one ever looked at). The cumulative tax was enormous and
benefitted no user.

The total deploy time dropped from "fourteen separate pipelines" to "one
pipeline that runs in three minutes." The cognitive load on whoever's
on-call dropped to "one service to keep healthy."

## When microservices make sense

Genuine scale boundaries — different teams, different SLAs, different
storage tiers, different release cadences. None of those applied to our
internal tools, all of which were built and maintained by the same five
people.

The monolith-to-microservice spectrum has a sweet spot, and it's not
"every tool is a service." It's "the granularity of your team and your
release cadence."
