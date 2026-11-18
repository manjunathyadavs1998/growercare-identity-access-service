-- SPEC-IAM-02 user directory: name search (expand only).
-- q matches the start of any name word (LIKE 'x%' or LIKE '% x%'). A btree can only serve the first form, so the name
-- gets a trigram GIN index, which serves both (pg_trgm is a trusted extension: the database owner may create it).
CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;
CREATE INDEX IF NOT EXISTS user_account_name_trgm_ix ON iam.user_account USING gin (lower(display_name) public.gin_trgm_ops);
