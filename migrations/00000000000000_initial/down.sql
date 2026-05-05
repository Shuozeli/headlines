-- Reverse of 00000000000000_initial/up.sql.
-- Drop tables in reverse FK order; DROP TABLE cascades indexes and constraints.

DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS tso_high_water;
DROP TABLE IF EXISTS system_keys;
DROP TABLE IF EXISTS system_scopes;
DROP TABLE IF EXISTS systems;
DROP TABLE IF EXISTS feed_recommendation;
DROP TABLE IF EXISTS follows;
DROP TABLE IF EXISTS user_keys;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS drafts;
DROP TABLE IF EXISTS article_versions;
DROP TABLE IF EXISTS articles_tombstone;
DROP TABLE IF EXISTS articles_live;
DROP TABLE IF EXISTS articles;
DROP TABLE IF EXISTS account_keys;
DROP TABLE IF EXISTS accounts;
