#include "Storage.h"

#include <sqlcipher/sqlite3.h>

#include <stdexcept>

#include "generated/schema_sql.h"

namespace signal2sip {

namespace {

// RAII wrapper around sqlite3_stmt so every early-return/throw below still
// finalizes the statement.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("sqlite3_prepare_v2 failed: ") + sqlite3_errmsg(db));
        }
    }
    ~Stmt() { sqlite3_finalize(stmt_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    operator sqlite3_stmt*() const { return stmt_; }

private:
    sqlite3_stmt* stmt_ = nullptr;
};

void bindText(sqlite3_stmt* stmt, int index, const std::string& value) {
    sqlite3_bind_text(stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

void bindTextOpt(sqlite3_stmt* stmt, int index, const std::optional<std::string>& value) {
    if (value) bindText(stmt, index, *value);
    else sqlite3_bind_null(stmt, index);
}

void bindBlob(sqlite3_stmt* stmt, int index, const Bytes& value) {
    sqlite3_bind_blob(stmt, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
}

void bindBlobOpt(sqlite3_stmt* stmt, int index, const std::optional<Bytes>& value) {
    if (value) bindBlob(stmt, index, *value);
    else sqlite3_bind_null(stmt, index);
}

void bindInt64Opt(sqlite3_stmt* stmt, int index, const std::optional<int64_t>& value) {
    if (value) sqlite3_bind_int64(stmt, index, *value);
    else sqlite3_bind_null(stmt, index);
}

std::string columnText(sqlite3_stmt* stmt, int index) {
    const unsigned char* text = sqlite3_column_text(stmt, index);
    int len = sqlite3_column_bytes(stmt, index);
    return text ? std::string(reinterpret_cast<const char*>(text), len) : std::string();
}

std::optional<std::string> columnTextOpt(sqlite3_stmt* stmt, int index) {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) return std::nullopt;
    return columnText(stmt, index);
}

Bytes columnBlob(sqlite3_stmt* stmt, int index) {
    const void* blob = sqlite3_column_blob(stmt, index);
    int len = sqlite3_column_bytes(stmt, index);
    const auto* bytes = static_cast<const uint8_t*>(blob);
    return blob ? Bytes(bytes, bytes + len) : Bytes();
}

std::optional<Bytes> columnBlobOpt(sqlite3_stmt* stmt, int index) {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) return std::nullopt;
    return columnBlob(stmt, index);
}

std::optional<int64_t> columnInt64Opt(sqlite3_stmt* stmt, int index) {
    if (sqlite3_column_type(stmt, index) == SQLITE_NULL) return std::nullopt;
    return sqlite3_column_int64(stmt, index);
}

} // namespace

Storage::Storage(const std::string& path, const std::string& key) {
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        std::string err = sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("sqlite3_open failed: " + err);
    }

    // PRAGMA key must be the very first statement executed on this
    // connection (SQLCipher applies it lazily on first real access, but
    // ordering it first avoids ever touching an unencrypted temp state).
    // PRAGMA statements don't support bound parameters, so the key is
    // safely quoted as an SQL string literal via sqlite3_mprintf's %Q
    // instead (handles embedded quotes correctly).
    {
        char* sql = sqlite3_mprintf("PRAGMA key = %Q", key.c_str());
        char* errmsg = nullptr;
        int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &errmsg);
        sqlite3_free(sql);
        if (rc != SQLITE_OK) {
            std::string err = errmsg ? errmsg : "unknown error";
            sqlite3_free(errmsg);
            sqlite3_close(db_);
            db_ = nullptr;
            throw std::runtime_error("PRAGMA key failed: " + err);
        }
    }

    // Cheapest way to confirm the key is actually correct: SQLCipher only
    // fails to decrypt on first real table access, not on PRAGMA key itself.
    char* errmsg = nullptr;
    if (sqlite3_exec(db_, "SELECT count(*) FROM sqlite_master", nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("failed to open database (wrong key or corrupt file): " + err);
    }

    if (sqlite3_exec(db_, kSchemaSql, nullptr, nullptr, &errmsg) != SQLITE_OK) {
        std::string err = errmsg ? errmsg : "unknown error";
        sqlite3_free(errmsg);
        sqlite3_close(db_);
        db_ = nullptr;
        throw std::runtime_error("failed to apply schema: " + err);
    }
}

Storage::~Storage() {
    if (db_) sqlite3_close(db_);
}

bool Storage::hasAccount() {
    Stmt stmt(db_, "SELECT count(*) FROM account WHERE id = 1");
    sqlite3_step(stmt);
    return sqlite3_column_int(stmt, 0) > 0;
}

AccountRecord Storage::loadAccount() {
    Stmt stmt(db_,
        "SELECT e164, aci, pni, device_id, password, registration_id, pni_registration_id, "
        "flow, account_entropy_pool, media_root_backup_key, profile_key, "
        "registered_at, linked_at, prekeys_refreshed_at "
        "FROM account WHERE id = 1");
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        throw std::runtime_error("loadAccount: no account row present");
    }
    AccountRecord account;
    account.e164 = columnText(stmt, 0);
    account.aci = columnText(stmt, 1);
    account.pni = columnText(stmt, 2);
    account.device_id = sqlite3_column_int(stmt, 3);
    account.password = columnText(stmt, 4);
    account.registration_id = sqlite3_column_int64(stmt, 5);
    account.pni_registration_id = sqlite3_column_int64(stmt, 6);
    account.flow = columnTextOpt(stmt, 7);
    account.account_entropy_pool = columnTextOpt(stmt, 8);
    account.media_root_backup_key = columnBlobOpt(stmt, 9);
    account.profile_key = columnBlobOpt(stmt, 10);
    account.registered_at = columnInt64Opt(stmt, 11);
    account.linked_at = columnInt64Opt(stmt, 12);
    account.prekeys_refreshed_at = columnInt64Opt(stmt, 13);
    return account;
}

void Storage::saveAccount(const AccountRecord& account) {
    Stmt stmt(db_,
        "INSERT INTO account (id, e164, aci, pni, device_id, password, registration_id, "
        "pni_registration_id, flow, account_entropy_pool, media_root_backup_key, profile_key, "
        "registered_at, linked_at, prekeys_refreshed_at) "
        "VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (id) DO UPDATE SET "
        "e164 = excluded.e164, aci = excluded.aci, pni = excluded.pni, "
        "device_id = excluded.device_id, password = excluded.password, "
        "registration_id = excluded.registration_id, pni_registration_id = excluded.pni_registration_id, "
        "flow = excluded.flow, account_entropy_pool = excluded.account_entropy_pool, "
        "media_root_backup_key = excluded.media_root_backup_key, profile_key = excluded.profile_key, "
        "registered_at = excluded.registered_at, linked_at = excluded.linked_at, "
        "prekeys_refreshed_at = excluded.prekeys_refreshed_at");
    bindText(stmt, 1, account.e164);
    bindText(stmt, 2, account.aci);
    bindText(stmt, 3, account.pni);
    sqlite3_bind_int(stmt, 4, account.device_id);
    bindText(stmt, 5, account.password);
    sqlite3_bind_int64(stmt, 6, account.registration_id);
    sqlite3_bind_int64(stmt, 7, account.pni_registration_id);
    bindTextOpt(stmt, 8, account.flow);
    bindTextOpt(stmt, 9, account.account_entropy_pool);
    bindBlobOpt(stmt, 10, account.media_root_backup_key);
    bindBlobOpt(stmt, 11, account.profile_key);
    bindInt64Opt(stmt, 12, account.registered_at);
    bindInt64Opt(stmt, 13, account.linked_at);
    bindInt64Opt(stmt, 14, account.prekeys_refreshed_at);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveAccount failed: ") + sqlite3_errmsg(db_));
    }
}

void Storage::saveIdentityKeypair(const std::string& identity, const IdentityKeypairRecord& keypair) {
    Stmt stmt(db_,
        "INSERT INTO identity_keypair (identity, private_key, public_key) VALUES (?, ?, ?) "
        "ON CONFLICT (identity) DO UPDATE SET private_key = excluded.private_key, public_key = excluded.public_key");
    bindText(stmt, 1, identity);
    bindBlob(stmt, 2, keypair.private_key);
    bindBlob(stmt, 3, keypair.public_key);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveIdentityKeypair failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<IdentityKeypairRecord> Storage::loadIdentityKeypair(const std::string& identity) {
    Stmt stmt(db_, "SELECT private_key, public_key FROM identity_keypair WHERE identity = ?");
    bindText(stmt, 1, identity);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    IdentityKeypairRecord keypair;
    keypair.private_key = columnBlob(stmt, 0);
    keypair.public_key = columnBlob(stmt, 1);
    return keypair;
}

void Storage::saveSignedPrekey(const std::string& identity, const SignedPrekeyRecord& prekey) {
    Stmt stmt(db_,
        "INSERT INTO signed_prekey (identity, key_id, record) VALUES (?, ?, ?) "
        "ON CONFLICT (identity) DO UPDATE SET key_id = excluded.key_id, record = excluded.record");
    bindText(stmt, 1, identity);
    sqlite3_bind_int64(stmt, 2, prekey.key_id);
    bindBlob(stmt, 3, prekey.record);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveSignedPrekey failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<SignedPrekeyRecord> Storage::loadSignedPrekey(const std::string& identity) {
    Stmt stmt(db_, "SELECT key_id, record FROM signed_prekey WHERE identity = ?");
    bindText(stmt, 1, identity);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    SignedPrekeyRecord prekey;
    prekey.key_id = sqlite3_column_int64(stmt, 0);
    prekey.record = columnBlob(stmt, 1);
    return prekey;
}

void Storage::saveKyberPrekey(const std::string& identity, const KyberPrekeyRecord& prekey) {
    Stmt stmt(db_,
        "INSERT INTO kyber_prekey (identity, key_id, record) VALUES (?, ?, ?) "
        "ON CONFLICT (identity) DO UPDATE SET key_id = excluded.key_id, record = excluded.record");
    bindText(stmt, 1, identity);
    sqlite3_bind_int64(stmt, 2, prekey.key_id);
    bindBlob(stmt, 3, prekey.record);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveKyberPrekey failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<KyberPrekeyRecord> Storage::loadKyberPrekey(const std::string& identity) {
    Stmt stmt(db_, "SELECT key_id, record FROM kyber_prekey WHERE identity = ?");
    bindText(stmt, 1, identity);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    KyberPrekeyRecord prekey;
    prekey.key_id = sqlite3_column_int64(stmt, 0);
    prekey.record = columnBlob(stmt, 1);
    return prekey;
}

void Storage::saveSession(const std::string& address, const Bytes& record) {
    Stmt stmt(db_,
        "INSERT INTO session (address, record) VALUES (?, ?) "
        "ON CONFLICT (address) DO UPDATE SET record = excluded.record");
    bindText(stmt, 1, address);
    bindBlob(stmt, 2, record);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveSession failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<Bytes> Storage::loadSession(const std::string& address) {
    Stmt stmt(db_, "SELECT record FROM session WHERE address = ?");
    bindText(stmt, 1, address);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    return columnBlob(stmt, 0);
}

std::vector<int> Storage::knownDeviceIdsFor(const std::string& serviceId) {
    Stmt stmt(db_, "SELECT address FROM session WHERE address LIKE ?");
    std::string pattern = serviceId + ".%";
    bindText(stmt, 1, pattern);
    std::vector<int> deviceIds;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string address = columnText(stmt, 0);
        auto dot = address.rfind('.');
        if (dot == std::string::npos) continue;
        try {
            deviceIds.push_back(std::stoi(address.substr(dot + 1)));
        } catch (...) {
            // not a plain integer suffix - ignore, matches the Node
            // prototype's Number.isInteger() filter.
        }
    }
    return deviceIds;
}

void Storage::saveRemoteIdentity(const std::string& address, const Bytes& publicKey) {
    Stmt stmt(db_,
        "INSERT INTO remote_identity (address, public_key) VALUES (?, ?) "
        "ON CONFLICT (address) DO UPDATE SET public_key = excluded.public_key");
    bindText(stmt, 1, address);
    bindBlob(stmt, 2, publicKey);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        throw std::runtime_error(std::string("saveRemoteIdentity failed: ") + sqlite3_errmsg(db_));
    }
}

std::optional<Bytes> Storage::loadRemoteIdentity(const std::string& address) {
    Stmt stmt(db_, "SELECT public_key FROM remote_identity WHERE address = ?");
    bindText(stmt, 1, address);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    return columnBlob(stmt, 0);
}

} // namespace signal2sip
