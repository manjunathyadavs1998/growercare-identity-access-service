-- SPEC-IAM-02 user directory: name-prefix search (expand only).
CREATE INDEX IF NOT EXISTS user_account_name_ix ON iam.user_account (lower(display_name) text_pattern_ops);
