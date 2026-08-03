-- signal2sip account/session storage schema.
--
-- Mirrors the field set of the Node prototype's per-account JSON files
-- (layer1/accountStore.js's saveAccount()/loadAccount(), confirmed against
-- the two real accounts already registered/linked this project:
-- +380000000001 standalone-registered, +380000000002 linked-as-device) and
-- protocolStores.js's sessions/identities file, byte-for-byte compatible in
-- meaning so existing accounts can be migrated in with a one-time import
-- script rather than re-registering.
--
-- One physical database file is now shared by every account the daemon
-- manages (see project decision: single-process multi-account, and the
-- shared-DB follow-up) - every table is namespaced by `account_name`
-- (the same free-form label used as the `[account.<name>]` config
-- section suffix) so two accounts' sessions/keys/identities never
-- collide even if they happen to reference the same remote serviceId.

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS account (
    account_name            TEXT PRIMARY KEY,
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

-- Identity keypairs: one row per (account_name, identity in {'aci','pni'}).
-- Private key never leaves this table/this process, matching the Node
-- prototype's aciIdentityKeyPair/pniIdentityKeyPair fields.
CREATE TABLE IF NOT EXISTS identity_keypair (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    identity        TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    private_key     BLOB NOT NULL,
    public_key      BLOB NOT NULL,
    PRIMARY KEY (account_name, identity)
);

-- Current signed prekey per (account_name, identity). Only the most
-- recent one is ever needed (matches AccountSignedPreKeyStore's
-- single-record behavior in the Node prototype) - refreshing overwrites
-- the row rather than appending.
CREATE TABLE IF NOT EXISTS signed_prekey (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    identity        TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    key_id          INTEGER NOT NULL,
    record          BLOB NOT NULL,          -- serialized SignedPreKeyRecord
    PRIMARY KEY (account_name, identity)
);

-- Last-resort Kyber (post-quantum) prekey per (account_name, identity) -
-- reusable by design, never marked "used" (matches AccountKyberPreKeyStore).
CREATE TABLE IF NOT EXISTS kyber_prekey (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    identity        TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
    key_id          INTEGER NOT NULL,
    record          BLOB NOT NULL,          -- serialized KyberPreKeyRecord
    PRIMARY KEY (account_name, identity)
);

-- Established sessions, keyed by (account_name, remote ProtocolAddress)
-- ("<serviceId>.<deviceId>", matching FileSessionStore's address.toString()
-- keys) so knownDeviceIdsFor()'s "scan the session-key namespace" query
-- becomes a simple LIKE prefix match (scoped to one account_name) instead
-- of a JSON key scan.
CREATE TABLE IF NOT EXISTS session (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    address         TEXT NOT NULL,          -- e.g. "<serviceId>.<deviceId>"
    record          BLOB NOT NULL,          -- serialized SessionRecord
    PRIMARY KEY (account_name, address)
);

-- Trusted remote identity keys (trust-on-first-use, matching
-- AccountIdentityStore.isTrustedIdentity's semantics exactly: absent means
-- "not yet seen, trust and record"; present means "must match exactly").
-- Namespaced per account_name too - two of our own accounts talking to the
-- same remote serviceId each keep their own trust-on-first-use record.
CREATE TABLE IF NOT EXISTS remote_identity (
    account_name    TEXT NOT NULL REFERENCES account(account_name),
    address         TEXT NOT NULL,          -- serviceId (not deviceId-qualified)
    public_key      BLOB NOT NULL,
    PRIMARY KEY (account_name, address)
);
