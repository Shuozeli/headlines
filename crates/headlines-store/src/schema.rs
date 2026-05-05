// @generated automatically by Diesel CLI.

diesel::table! {
    use diesel::sql_types::*;

    account_keys (account_id, key_id) {
        account_id -> Uuid,
        key_id -> Uuid,
        algo -> Text,
        public_key -> Text,
        status -> Text,
        created_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    accounts (id) {
        id -> Uuid,
        short_name -> Text,
        author_name -> Text,
        author_url -> Nullable<Text>,
        status -> Text,
        deleted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    article_versions (article_id, version) {
        article_id -> Uuid,
        version -> Int4,
        title -> Text,
        author_name -> Nullable<Text>,
        author_url -> Nullable<Text>,
        content -> Nullable<Jsonb>,
        redacted_at -> Nullable<Timestamptz>,
        redaction_reason -> Nullable<Text>,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    articles (id) {
        id -> Uuid,
        account_id -> Uuid,
        state -> Text,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    articles_live (article_id) {
        article_id -> Uuid,
        current_version -> Int4,
        published_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    articles_tombstone (article_id) {
        article_id -> Uuid,
        reason -> Nullable<Text>,
        tombstoned_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    drafts (id) {
        id -> Uuid,
        account_id -> Uuid,
        title -> Text,
        author_name -> Nullable<Text>,
        author_url -> Nullable<Text>,
        content -> Jsonb,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    events (id) {
        id -> Uuid,
        user_id -> Uuid,
        article_id -> Nullable<Uuid>,
        #[sql_name = "type"]
        type_ -> Text,
        occurred_at -> Timestamptz,
        received_at -> Timestamptz,
        surface -> Text,
        properties -> Jsonb,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    feed_recommendation (user_id, position) {
        user_id -> Uuid,
        position -> Int4,
        article_id -> Uuid,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    follows (user_id, account_id) {
        user_id -> Uuid,
        account_id -> Uuid,
        status -> Text,
        created_at -> Timestamptz,
        unfollowed_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    system_keys (system_id, key_id) {
        system_id -> Uuid,
        key_id -> Uuid,
        algo -> Text,
        public_key -> Text,
        status -> Text,
        created_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    system_scopes (system_id, scope) {
        system_id -> Uuid,
        scope -> Text,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    systems (id) {
        id -> Uuid,
        name -> Text,
        status -> Text,
        created_at -> Timestamptz,
        disabled_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    tso_high_water (id) {
        id -> Text,
        last_physical_ms -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    user_keys (user_id, key_id) {
        user_id -> Uuid,
        key_id -> Uuid,
        algo -> Text,
        public_key -> Text,
        status -> Text,
        created_at -> Timestamptz,
        revoked_at -> Nullable<Timestamptz>,
    }
}

diesel::table! {
    use diesel::sql_types::*;

    users (id) {
        id -> Uuid,
        display_name -> Nullable<Text>,
        status -> Text,
        deleted_at -> Nullable<Timestamptz>,
        created_at -> Timestamptz,
    }
}

diesel::joinable!(account_keys -> accounts (account_id));
diesel::joinable!(article_versions -> articles (article_id));
diesel::joinable!(articles -> accounts (account_id));
diesel::joinable!(articles_live -> articles (article_id));
diesel::joinable!(articles_tombstone -> articles (article_id));
diesel::joinable!(drafts -> accounts (account_id));
diesel::joinable!(feed_recommendation -> users (user_id));
diesel::joinable!(follows -> accounts (account_id));
diesel::joinable!(follows -> users (user_id));
diesel::joinable!(system_keys -> systems (system_id));
diesel::joinable!(system_scopes -> systems (system_id));
diesel::joinable!(user_keys -> users (user_id));

diesel::allow_tables_to_appear_in_same_query!(
    account_keys,
    accounts,
    article_versions,
    articles,
    articles_live,
    articles_tombstone,
    drafts,
    events,
    feed_recommendation,
    follows,
    system_keys,
    system_scopes,
    systems,
    tso_high_water,
    user_keys,
    users,
);
