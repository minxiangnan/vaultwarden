-- Standalone authenticator (TOTP) entries.
-- name, issuer, secret, and notes are client-encrypted EncStrings stored opaquely.
-- LONGTEXT matches the 100000 character application limit (TEXT is only 64 KiB).
CREATE TABLE authenticator_entries (
    uuid          CHAR(36)    NOT NULL PRIMARY KEY,
    user_uuid     CHAR(36)    NOT NULL,
    name          LONGTEXT    NOT NULL,
    issuer        LONGTEXT,
    secret        LONGTEXT    NOT NULL,
    algorithm     VARCHAR(10) NOT NULL,
    digits        INTEGER     NOT NULL DEFAULT 6,
    period        INTEGER     NOT NULL DEFAULT 30,
    notes         LONGTEXT,
    favorite      BOOLEAN     NOT NULL DEFAULT 0,
    sort_order    INTEGER     NOT NULL DEFAULT 0,
    revision_date DATETIME    NOT NULL,
    creation_date DATETIME    NOT NULL,
    FOREIGN KEY (user_uuid) REFERENCES users (uuid) ON DELETE CASCADE
);

CREATE INDEX authenticator_entries_user_uuid_idx ON authenticator_entries (user_uuid);
