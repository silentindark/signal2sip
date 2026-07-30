-- signal2sip account/session storage schema.
--
-- Mirrors the field set of the Node prototype's per-account JSON files
-- (layer1/accountStore.js's saveAccount()/loadAccount(), confirmed against
-- the two real accounts already registered/linked this project:
-- +123456789004 standalone-registered, +123456789002 linked-as-device) and
-- protocolStores.js's sessions/identities file, byte-for-byte compatible in
-- meaning so existing accounts can be migrated in with a one-time import
-- script rather than re-registering.
--
-- One signal2sip process handles exactly one account (see project decision
-- in memory: N processes, one per account, mirroring tg2sip-webrtc's own
-- model) - so this schema does not need an accounts table keyed by label;
-- `account` is a single-row table. Everything else is keyed by identity
-- ('aci' or 'pni' - see PROTOCOL.md) and/or remote address where relevant.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS account (
    id                      INTEGER PRIMARY KEY CHECK (id = 1), -- single row
    e164                    TEXT NOT NULL,
    aci                     TEXT NOT NULL,
    pni                     TEXT NOT NULL,
    device_id               INTEGER NOT NULL,
    password                TEXT NOT NULL,
    registration_id          INTEGER NOT NULL,
    pni_registration_id      INTEGER NOT NULL,
    flow                    TEXT,            -- 'standalone' | 'linked' | NULL
    account_entropy_pool     TEXT,            -- linked accounts only
    media_root_backup_key    BLOB,            -- linked accounts only
    profile_key             BLOB,
    registered_at            INTEGER,         -- unix seconds, standalone registration
    linked_at               INTEGER,         -- unix seconds, device-linking
    prekeys_refreshed_at     INTEGER
);

-- Identity keypairs: one row per (identity in {'aci','pni'}). Private key
-- never leaves this table/this process, matching the Node prototype's
-- aciIdentityKeyPair/pniIdentityKeyPair fields.
CREATE TABLE IF NOT EXISTS identity_keypair (
    identity        TEXT PRIMARY KEY CHECK (identity IN ('aci', 'pni')),
    private_key     BLOB NOT NULL,
    public_key      BLOB NOT NULL
);

-- Current signed prekey per identity. Only the most recent one is ever
-- needed (matches AccountSignedPreKeyStore's single-record behavior in the
-- Node prototype) - refreshing overwrites the row rather than appending.
CREATE TABLE IF NOT EXISTS signed_prekey (
    identity        TEXT PRIMARY KEY CHECK (identity IN ('aci', 'pni')),
    key_id          INTEGER NOT NULL,
    record          BLOB NOT NULL          -- serialized SignedPreKeyRecord
);

-- Last-resort Kyber (post-quantum) prekey per identity - reusable by
-- design, never marked "used" (matches AccountKyberPreKeyStore).
CREATE TABLE IF NOT EXISTS kyber_prekey (
    identity        TEXT PRIMARY KEY CHECK (identity IN ('aci', 'pni')),
    key_id          INTEGER NOT NULL,
    record          BLOB NOT NULL          -- serialized KyberPreKeyRecord
);

-- Established sessions, keyed by full remote ProtocolAddress
-- ("<serviceId>.<deviceId>", matching FileSessionStore's address.toString()
-- keys) so knownDeviceIdsFor()'s "scan the session-key namespace" query
-- becomes a simple LIKE prefix match instead of a JSON key scan.
CREATE TABLE IF NOT EXISTS session (
    address         TEXT PRIMARY KEY,      -- e.g. "<serviceId>.<deviceId>"
    record          BLOB NOT NULL          -- serialized SessionRecord
);

-- Trusted remote identity keys (trust-on-first-use, matching
-- AccountIdentityStore.isTrustedIdentity's semantics exactly: absent means
-- "not yet seen, trust and record"; present means "must match exactly").
CREATE TABLE IF NOT EXISTS remote_identity (
    address         TEXT PRIMARY KEY,      -- serviceId (not deviceId-qualified)
    public_key      BLOB NOT NULL
);
