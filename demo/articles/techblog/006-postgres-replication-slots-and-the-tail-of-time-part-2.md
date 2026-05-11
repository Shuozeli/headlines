---
title: "Postgres Replication Slots and the Tail of Time: Part 2"
author_name: "Zora Lin"
author_url: "https://example.com"
created_at: "2026-04-27T16:18:00Z"
state: "live"
---

**Followup:** since publishing the original I've learned a few more things worth recording.


Replication slots are the silent rails of every Postgres deployment doing
streaming replication, logical decoding, or change-data-capture into Kafka.
They're also the most common cause of disk-fills at 3 AM.

When you create a logical replication slot for, say, a CDC pipeline,
Postgres reserves WAL from the slot's `restart_lsn` forward. The
`pg_replication_slots.confirmed_flush_lsn` advances as the consumer
acknowledges receipt. If the consumer pauses, all WAL between flush and
HEAD stays on disk until the consumer comes back.

## How slots accumulate

A slot is a server-side bookmark that tells Postgres: "this consumer is
still going to read this WAL position, so don't recycle the segments yet."
Forgetting to drop a slot when its consumer dies is exactly equivalent to
filling your disk with logs you'll never read.

`pg_wal/` grows. Sometimes by gigabytes per minute on a busy database.

## Diagnosing a stuck slot

Run this query first whenever a Postgres instance shows surprise disk
pressure:

```sql
SELECT slot_name, active, restart_lsn,
       pg_size_pretty(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn)) AS lag_bytes
FROM pg_replication_slots
ORDER BY pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) DESC;
```

A row with `active=false` and a large `lag_bytes` is the smoking gun.

## Recovery

You have two options. Drop the slot — fast, simple, but the consumer will
need to do a full snapshot when it comes back. Or restart the consumer and
let it drain — slower, but preserves continuity.

In practice we've found that pre-flight automation (a timer that drops
slots inactive for more than an hour) is worth its weight in pages.
