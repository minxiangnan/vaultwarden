-- Standalone authenticator (TOTP) entries.
-- name, issuer, secret, and notes are client-encrypted EncStrings stored opaquely.
CREATE TABLE authenticator_entries (
    uuid          CHAR(36)  NOT NULL PRIMARY KEY,
    user_uuid     CHAR(36)  NOT NULL REFERENCES users (uuid) ON DELETE CASCADE,
    name          TEXT      NOT NULL,
    issuer        TEXT,
    secret        TEXT      NOT NULL,
    algorithm     TEXT      NOT NULL,
    digits        INTEGER   NOT NULL DEFAULT 6,
    period        INTEGER   NOT NULL DEFAULT 30,
    notes         TEXT,
    favorite      BOOLEAN   NOT NULL DEFAULT FALSE,
    sort_order    INTEGER   NOT NULL DEFAULT 0,
    revision_date TIMESTAMP NOT NULL,
    creation_date TIMESTAMP NOT NULL
);

CREATE INDEX authenticator_entries_user_uuid_idx ON authenticator_entries (user_uuid);
