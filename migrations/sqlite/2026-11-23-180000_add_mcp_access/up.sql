-- MCP access is opt-in. These tables store a hash of the access token and TOTP
-- secrets re-encrypted to a key derived from that token. They do not store the token
-- or the plaintext secret. Vault EncStrings in authenticator_entries are untouched.
CREATE TABLE mcp_tokens (
    uuid        TEXT     NOT NULL PRIMARY KEY,
    user_uuid   TEXT     NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    token_hash  TEXT     NOT NULL UNIQUE,
    key_salt    TEXT     NOT NULL,
    token_enc   TEXT,
    label       TEXT,
    created_at  DATETIME NOT NULL,
    revoked_at  DATETIME
);

CREATE INDEX mcp_tokens_user_uuid_idx ON mcp_tokens (user_uuid);

CREATE TABLE mcp_entries (
    uuid         TEXT     NOT NULL PRIMARY KEY,
    user_uuid    TEXT     NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    source       TEXT     NOT NULL,
    source_id    TEXT     NOT NULL,
    alias        TEXT     NOT NULL,
    secret_ct    TEXT     NOT NULL,
    issuer_ct    TEXT,
    account_ct   TEXT,
    host_ct      TEXT,
    algorithm    TEXT     NOT NULL,
    digits       INTEGER  NOT NULL,
    period       INTEGER  NOT NULL,
    steam        BOOLEAN  NOT NULL DEFAULT 0,
    created_at   DATETIME NOT NULL,
    updated_at   DATETIME NOT NULL,
    UNIQUE (user_uuid, alias),
    UNIQUE (user_uuid, source, source_id)
);

CREATE INDEX mcp_entries_user_uuid_idx ON mcp_entries (user_uuid);

CREATE TABLE mcp_audit (
    uuid        TEXT     NOT NULL PRIMARY KEY,
    user_uuid   TEXT     REFERENCES users (uuid) ON DELETE CASCADE,
    token_uuid  TEXT,
    action      TEXT     NOT NULL,
    alias       TEXT,
    success     BOOLEAN  NOT NULL,
    detail      TEXT,
    ip          TEXT,
    created_at  DATETIME NOT NULL
);

CREATE INDEX mcp_audit_user_uuid_idx ON mcp_audit (user_uuid, created_at);
