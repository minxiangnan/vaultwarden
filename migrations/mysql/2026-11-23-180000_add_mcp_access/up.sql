CREATE TABLE mcp_tokens (
    uuid        CHAR(36)     NOT NULL PRIMARY KEY,
    user_uuid   CHAR(36)     NOT NULL,
    token_hash  VARCHAR(64)  NOT NULL,
    key_salt    VARCHAR(64)  NOT NULL,
    token_enc   LONGTEXT,
    label       VARCHAR(64),
    created_at  DATETIME     NOT NULL,
    revoked_at  DATETIME,
    UNIQUE KEY mcp_tokens_token_hash_idx (token_hash),
    FOREIGN KEY (user_uuid) REFERENCES users (uuid) ON DELETE CASCADE
);

CREATE INDEX mcp_tokens_user_uuid_idx ON mcp_tokens (user_uuid);

CREATE TABLE mcp_entries (
    uuid         CHAR(36)     NOT NULL PRIMARY KEY,
    user_uuid    CHAR(36)     NOT NULL,
    source       VARCHAR(20)  NOT NULL,
    source_id    VARCHAR(36)  NOT NULL,
    alias        VARCHAR(64)  NOT NULL,
    secret_ct    LONGTEXT     NOT NULL,
    issuer_ct    LONGTEXT,
    account_ct   LONGTEXT,
    host_ct      LONGTEXT,
    algorithm    VARCHAR(10)  NOT NULL,
    digits       INTEGER      NOT NULL,
    period       INTEGER      NOT NULL,
    steam        BOOLEAN      NOT NULL DEFAULT 0,
    created_at   DATETIME     NOT NULL,
    updated_at   DATETIME     NOT NULL,
    UNIQUE KEY mcp_entries_alias_idx (user_uuid, alias),
    UNIQUE KEY mcp_entries_source_idx (user_uuid, source, source_id),
    FOREIGN KEY (user_uuid) REFERENCES users (uuid) ON DELETE CASCADE
);

CREATE INDEX mcp_entries_user_uuid_idx ON mcp_entries (user_uuid);

CREATE TABLE mcp_audit (
    uuid        CHAR(36)     NOT NULL PRIMARY KEY,
    user_uuid   CHAR(36),
    token_uuid  CHAR(36),
    action      VARCHAR(32)  NOT NULL,
    alias       VARCHAR(64),
    success     BOOLEAN      NOT NULL,
    detail      VARCHAR(300),
    ip          VARCHAR(64),
    created_at  DATETIME     NOT NULL,
    FOREIGN KEY (user_uuid) REFERENCES users (uuid) ON DELETE CASCADE
);

CREATE INDEX mcp_audit_user_uuid_idx ON mcp_audit (user_uuid, created_at);
