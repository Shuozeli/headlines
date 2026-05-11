---
title: "Building a Fault-Tolerant Worker Queue with Postgres: Refresh"
author_name: "Felix Romero"
author_url: "https://example.com"
created_at: "2026-04-25T18:28:00Z"
state: "live"
---

**Followup:** since publishing the original I've learned a few more things worth recording.


Postgres is a remarkably good worker queue when you don't need queue
features that Postgres doesn't have. This tutorial walks through
building one in about 200 lines of Rust.

```sql
CREATE TABLE jobs (
    id          uuid PRIMARY KEY,
    queue       text        NOT NULL,
    priority    integer     NOT NULL DEFAULT 5,
    payload     jsonb       NOT NULL,
    state       text        NOT NULL CHECK (state IN ('ready', 'in_flight', 'done', 'dead')),
    attempts    integer     NOT NULL DEFAULT 0,
    locked_at   timestamptz,
    locked_by   text,
    available_at timestamptz NOT NULL DEFAULT now(),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

## Schema

The features we want: at-least-once delivery, visibility timeout (a
worker that crashes mid-task should release the row), priority,
backoff on retries, and a dead-letter table for poison messages. None
of these are exotic.

CREATE INDEX jobs_ready ON jobs (queue, priority, available_at)
    WHERE state = 'ready';
```

The partial index is the secret to making `SELECT FOR UPDATE SKIP
LOCKED` cheap; we're only ever scanning rows that are actually
available.

## The fetch query

```sql
WITH next AS (
    SELECT id FROM jobs
    WHERE state = 'ready' AND queue = $1 AND available_at <= now()
    ORDER BY priority, available_at
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE jobs SET
    state = 'in_flight',
    locked_at = now(),
    locked_by = $2,
    attempts = attempts + 1
WHERE id = (SELECT id FROM next)
RETURNING *;
```

`SKIP LOCKED` is the key. Multiple workers can run this query
concurrently and each gets a distinct row.

## The Rust worker loop

```rust
loop {
    let job = fetch_next_job(&pool, "default", &worker_id).await?;
    match job {
        Some(j) => {
            match handle_job(&j).await {
                Ok(_) => mark_done(&pool, j.id).await?,
                Err(e) => mark_failed(&pool, j.id, &e.to_string()).await?,
            }
        }
        None => tokio::time::sleep(Duration::from_secs(1)).await,
    }
}
```

The `mark_failed` path is where backoff lives:

```sql
UPDATE jobs SET
    state = CASE WHEN attempts >= 5 THEN 'dead' ELSE 'ready' END,
    available_at = now() + (interval '1 second' * pow(2, attempts)),
    locked_at = NULL,
    locked_by = NULL
WHERE id = $1;
```

Exponential backoff. Five attempts then dead-letter.

## Visibility timeout

A separate sweep query rescues abandoned jobs:

```sql
UPDATE jobs SET
    state = 'ready',
    locked_at = NULL,
    locked_by = NULL
WHERE state = 'in_flight'
  AND locked_at < now() - interval '5 minutes';
```

Run this every minute. Workers should keep their jobs to under five
minutes; longer than that and the sweep will pull the row out from
under them, which is fine — at-least-once delivery is the contract.

## When to graduate to a real queue

Two reasons. First, throughput beyond a few thousand jobs per second
on a single Postgres makes the WAL hot. Second, if you genuinely need
exactly-once or strict ordering across queue partitions. Both of those
are real but uncommon problems. If you're not hitting them, Postgres
is great.

We've run this exact pattern at Acme Corp for three years across two
products. Total operational pages: zero. Total bugs traced to the
queue itself: one (a missing `FOR UPDATE`, fixed in twenty minutes).
