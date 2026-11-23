CREATE TABLE mcp_tokens (
    uuid        CHAR(36)  NOT NULL PRIMARY KEY,
    user_uuid   CHAR(36)  NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    token_hash  TEXT      NOT NULL UNIQUE,
    key_salt    TEXT      NOT NULL,
    token_enc   TEXT,
    label       TEXT,
    created_at  TIMESTAMP NOT NULL,
    revoked_at  TIMESTAMP
);

CREATE INDEX mcp_tokens_user_uuid_idx ON mcp_tokens (user_uuid);

CREATE TABLE mcp_entries (
    uuid         CHAR(36)  NOT NULL PRIMARY KEY,
    user_uuid    CHAR(36)  NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    source       TEXT      NOT NULL,
    source_id    TEXT      NOT NULL,
    alias        TEXT      NOT NULL,
    secret_ct    TEXT      NOT NULL,
    issuer_ct    TEXT,
    account_ct   TEXT,
    host_ct      TEXT,
    algorithm    TEXT      NOT NULL,
    digits       INTEGER   NOT NULL,
    period       INTEGER   NOT NULL,
    steam        BOOLEAN   NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMP NOT NULL,
    updated_at   TIMESTAMP NOT NULL,
    UNIQUE (user_uuid, alias),
    UNIQUE (user_uuid, source, source_id)
);

CREATE INDEX mcp_entries_user_uuid_idx ON mcp_entries (user_uuid);

CREATE TABLE mcp_audit (
    uuid        CHAR(36)  NOT NULL PRIMARY KEY,
    user_uuid   CHAR(36)  REFERENCES users (uuid) ON DELETE CASCADE,
    token_uuid  TEXT,
    action      TEXT      NOT NULL,
    alias       TEXT,
    success     BOOLEAN   NOT NULL,
    detail      TEXT,
    ip          TEXT,
    created_at  TIMESTAMP NOT NULL
);

CREATE INDEX mcp_audit_user_uuid_idx ON mcp_audit (user_uuid, created_at);
