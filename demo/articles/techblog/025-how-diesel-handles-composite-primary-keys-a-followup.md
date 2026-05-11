---
title: "How Diesel Handles Composite Primary Keys: A Followup"
author_name: "Zora Lin"
author_url: "https://example.com"
created_at: "2026-04-18T08:42:00Z"
state: "live"
---

**A note up front:** this piece extends an earlier post on the same topic with new examples.


Composite primary keys come up surprisingly often once you start modelling
real entities. A `(user_id, article_id)` follow edge or a `(account_id, key_id)`
key registry both want a multi-column primary key, and the ORM you reach for
ought to make that natural rather than awkward.

```rust
table! {
    follows (user_id, account_id) {
        user_id -> Uuid,
        account_id -> Uuid,
        status -> Text,
    }
}
```

## Defining the schema

Diesel's table macro accepts `primary_key(col_a, col_b, ...)` and emits the
right `Identifiable` impls for you. The key insight is that `Insertable` is
generated separately, so you can pass a struct without an `id` field at all
and Diesel will just use the columns you declare.

The macro internally derives the appropriate `BelongsTo` and `Associations`
plumbing. No further annotations are required.

## Querying with a composite key

```rust
follows::table
    .find((user_id, account_id))
    .first::<Follow>(&mut conn)
    .await
```

The `.find` method accepts a tuple matching the primary key columns in order.
This is one of the small but important ergonomic wins of Diesel over a
hand-rolled query builder.

## Caveats

Two gotchas worth knowing. First, `Insertable` doesn't auto-generate the
`(user_id, account_id)` tuple for `RETURNING` clauses if either column is
declared `NOT NULL DEFAULT ...`; you need to either drop the default or add
an explicit return type. Second, the `belongs_to` derive only takes a single
parent at a time — modelling many-to-many through a join table requires two
`belongs_to` derives stacked on the same struct.

Both are minor. After a year using Diesel against composite keys we've found
the ergonomics solid.
