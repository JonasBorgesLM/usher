-- 0001_initial_schema.sql
--
-- Users, refresh token families and their tokens, and consent (REQUIREMENTS
-- §7.1, ADR-0002, ADR-0005, ADR-0018). Registered OAuth clients are NOT a
-- table here: RF-01 makes them versioned configuration, loaded at startup —
-- client_id below is a plain TEXT column, never a foreign key, because there
-- is nothing in this database for it to reference.
--
-- gen_random_uuid() is built into Postgres core since 13 -- no pgcrypto
-- extension needed, and RNF's floor is Postgres 16.

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Canonicalized once in application code (RS-35) before it ever reaches
    -- this column; the uniqueness constraint is what makes "one identifier,
    -- one account" a database invariant rather than a hope.
    identifier    TEXT NOT NULL UNIQUE,
    -- PHC string ($argon2id$v=19$m=...,t=...,p=...$salt$hash, RS-13). Never a
    -- plain password, and never anything shorter than a real hash could be --
    -- the CHECK is a floor, not a format validator; the format is the
    -- application's job.
    password_hash TEXT NOT NULL CHECK (length(password_hash) >= 20),
    role          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per refresh-token lineage (RS-11). RevokedReason values are the
-- four docs/ARCHITECTURE.md §2.2 names; revoked_at and revoked_reason are set
-- together or not at all, which the CHECK below makes structural rather than
-- a convention every caller has to remember.
CREATE TABLE refresh_families (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id      TEXT NOT NULL,
    subject        UUID NOT NULL REFERENCES users (id),
    scope          TEXT[] NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL, -- absolute lifetime, RF-12
    revoked_at     TIMESTAMPTZ,
    revoked_reason TEXT
        CHECK (revoked_reason IS NULL OR revoked_reason IN (
            'reuse_detected', 'revoked_by_client', 'admin', 'consent_revoked'
        )),
    CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);

CREATE INDEX refresh_families_subject_idx ON refresh_families (subject);
CREATE INDEX refresh_families_client_idx ON refresh_families (client_id);

-- One row per issued token within a family. hash is the ONLY thing this
-- table ever stores for a token -- there is no column a raw refresh token
-- could be written to, and the CHECK on octet_length pins the column to
-- exactly SHA-256's output width (RS-10), so a value of the wrong shape is
-- rejected by the schema, not merely by review.
--
-- consumed_at is the column RS-11's whole guarantee rests on: the only way
-- to consume a token is
--
--   UPDATE refresh_tokens SET consumed_at = now()
--   WHERE hash = $1 AND consumed_at IS NULL;
--
-- checked by its affected-row count (1 = this exchange won the race, 0 =
-- the token was already consumed -- reuse). There is no SELECT before this
-- UPDATE anywhere in this schema or the code that queries it; docs/
-- ARCHITECTURE.md §2.2 repeats this exact statement next to FamilyStore.Rotate.
CREATE TABLE refresh_tokens (
    hash        BYTEA PRIMARY KEY CHECK (octet_length(hash) = 32),
    family_id   UUID NOT NULL REFERENCES refresh_families (id) ON DELETE CASCADE,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL, -- idle lifetime, RF-12
    consumed_at TIMESTAMPTZ
);

CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

-- One row per (user, client) grant (RF-13). Granting again replaces the row
-- rather than accumulating one per grant, matching ConsentStore.Grant's
-- "replaces any prior grant for the pair."
CREATE TABLE consent (
    user_id    UUID NOT NULL REFERENCES users (id),
    client_id  TEXT NOT NULL,
    scope      TEXT[] NOT NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id)
);
