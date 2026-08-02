#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace signal2sip {

using Bytes = std::vector<uint8_t>;

// Field names/meaning match layer1/accountStore.js's saved JSON exactly -
// see schema.sql for the full mapping rationale.
struct AccountRecord {
    std::string e164, aci, pni, password;
    int device_id = 0;
    int64_t registration_id = 0;
    int64_t pni_registration_id = 0;
    std::optional<std::string> flow;
    std::optional<std::string> account_entropy_pool;
    std::optional<Bytes> media_root_backup_key;
    std::optional<Bytes> profile_key;
    std::optional<int64_t> registered_at;
    std::optional<int64_t> linked_at;
    std::optional<int64_t> prekeys_refreshed_at;
};

struct IdentityKeypairRecord {
    Bytes private_key;
    Bytes public_key;
};

struct SignedPrekeyRecord {
    int64_t key_id = 0;
    Bytes record;
};

struct KyberPrekeyRecord {
    int64_t key_id = 0;
    Bytes record;
};

// Encrypted (SQLCipher) local storage, scoped to one Signal account via
// `accountName` - multiple Storage instances (one per account) can (and
// normally do) point at the same shared database file/path, each opening
// its own sqlite3 connection (SQLite/SQLCipher handle multiple
// connections to one file natively, same as any multi-process access).
// Every table is namespaced by account_name (see schema.sql) so two
// accounts' sessions/keys/identities never collide.
class Storage {
public:
    // Opens (creating if needed) the database at `path`, keyed with `key`
    // (passed to SQLCipher's `PRAGMA key`, which does its own KDF - callers
    // pass a human/config-supplied passphrase, not a raw derived key), and
    // ensures the schema exists. `accountName` scopes every row this
    // instance reads/writes - matches the `[account.<name>]` config
    // section suffix. Throws std::runtime_error on any failure, including
    // a wrong key against an existing database.
    Storage(const std::string& path, const std::string& key, const std::string& accountName);
    ~Storage();

    Storage(const Storage&) = delete;
    Storage& operator=(const Storage&) = delete;

    bool hasAccount();
    AccountRecord loadAccount();
    void saveAccount(const AccountRecord& account);

    // identity in {"aci", "pni"}
    void saveIdentityKeypair(const std::string& identity, const IdentityKeypairRecord& keypair);
    std::optional<IdentityKeypairRecord> loadIdentityKeypair(const std::string& identity);

    void saveSignedPrekey(const std::string& identity, const SignedPrekeyRecord& prekey);
    std::optional<SignedPrekeyRecord> loadSignedPrekey(const std::string& identity);

    void saveKyberPrekey(const std::string& identity, const KyberPrekeyRecord& prekey);
    std::optional<KyberPrekeyRecord> loadKyberPrekey(const std::string& identity);

    // address is "<serviceId>.<deviceId>", matching FileSessionStore's
    // ProtocolAddress::toString() keys.
    void saveSession(const std::string& address, const Bytes& record);
    std::optional<Bytes> loadSession(const std::string& address);

    // Mirrors protocolStores.js's knownDeviceIdsFor(): every device id we
    // have a session with for the given serviceId.
    std::vector<int> knownDeviceIdsFor(const std::string& serviceId);

    // address is a bare serviceId (not device-qualified) - trust-on-first-
    // use store, matching AccountIdentityStore's semantics.
    void saveRemoteIdentity(const std::string& address, const Bytes& publicKey);
    std::optional<Bytes> loadRemoteIdentity(const std::string& address);

private:
    sqlite3* db_ = nullptr;
    std::string accountName_;
};

} // namespace signal2sip
