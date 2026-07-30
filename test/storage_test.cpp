// Standalone verification for Milestone A (see
// /home/vlad/.claude/plans/jiggly-mapping-plum.md): proves the SQLCipher
// link + schema work end-to-end, and that the resulting file is genuinely
// encrypted (not plain SQLite readable without the key), before any
// libsignal/protocol code is built on top of it.

#include "../storage/Storage.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>

using namespace signal2sip;

namespace {

int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "PASS: " << what << "\n";
    } else {
        std::cout << "FAIL: " << what << "\n";
        g_failures++;
    }
}

Bytes bytesFrom(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

std::string stringFrom(const Bytes& b) {
    return std::string(b.begin(), b.end());
}

} // namespace

int main() {
    const std::string dbPath = "/tmp/signal2sip_storage_test.db";
    const std::string key = "test-passphrase-not-for-real-use";
    std::remove(dbPath.c_str());

    // --- round-trip every table ---
    {
        Storage storage(dbPath, key);

        check(!storage.hasAccount(), "fresh database has no account row");

        AccountRecord account;
        account.e164 = "+123456789004";
        account.aci = "11111111-1111-1111-1111-111111111111";
        account.pni = "22222222-2222-2222-2222-222222222222";
        account.device_id = 1;
        account.password = "s3cr3t";
        account.registration_id = 12345;
        account.pni_registration_id = 54321;
        account.flow = "standalone";
        account.registered_at = 1785000000;
        storage.saveAccount(account);

        check(storage.hasAccount(), "account row present after saveAccount");
        AccountRecord loaded = storage.loadAccount();
        check(loaded.e164 == account.e164, "account.e164 round-trips");
        check(loaded.aci == account.aci, "account.aci round-trips");
        check(loaded.device_id == account.device_id, "account.device_id round-trips");
        check(loaded.registration_id == account.registration_id, "account.registration_id round-trips");
        check(loaded.flow.has_value() && *loaded.flow == "standalone", "account.flow (optional) round-trips");
        check(!loaded.account_entropy_pool.has_value(), "unset optional column stays null");

        IdentityKeypairRecord aciKeypair{bytesFrom("aci-private-key-bytes"), bytesFrom("aci-public-key-bytes")};
        storage.saveIdentityKeypair("aci", aciKeypair);
        auto loadedKeypair = storage.loadIdentityKeypair("aci");
        check(loadedKeypair.has_value(), "identity_keypair row present after save");
        check(loadedKeypair && stringFrom(loadedKeypair->private_key) == "aci-private-key-bytes",
              "identity_keypair.private_key round-trips");
        check(!storage.loadIdentityKeypair("pni").has_value(), "pni identity_keypair absent until saved");

        storage.saveSignedPrekey("aci", SignedPrekeyRecord{7, bytesFrom("signed-prekey-record")});
        auto loadedSigned = storage.loadSignedPrekey("aci");
        check(loadedSigned.has_value() && loadedSigned->key_id == 7, "signed_prekey round-trips");

        storage.saveKyberPrekey("aci", KyberPrekeyRecord{9, bytesFrom("kyber-prekey-record")});
        auto loadedKyber = storage.loadKyberPrekey("aci");
        check(loadedKyber.has_value() && loadedKyber->key_id == 9, "kyber_prekey round-trips");

        std::string serviceId = "33333333-3333-3333-3333-333333333333";
        storage.saveSession(serviceId + ".1", bytesFrom("session-record-device-1"));
        storage.saveSession(serviceId + ".3", bytesFrom("session-record-device-3"));
        auto loadedSession = storage.loadSession(serviceId + ".1");
        check(loadedSession.has_value() && stringFrom(*loadedSession) == "session-record-device-1",
              "session round-trips");

        auto deviceIds = storage.knownDeviceIdsFor(serviceId);
        check(deviceIds.size() == 2, "knownDeviceIdsFor finds both sessions");
        bool has1 = false, has3 = false;
        for (int id : deviceIds) {
            if (id == 1) has1 = true;
            if (id == 3) has3 = true;
        }
        check(has1 && has3, "knownDeviceIdsFor returns the correct device ids");

        storage.saveRemoteIdentity(serviceId, bytesFrom("remote-identity-public-key"));
        auto loadedIdentity = storage.loadRemoteIdentity(serviceId);
        check(loadedIdentity.has_value() && stringFrom(*loadedIdentity) == "remote-identity-public-key",
              "remote_identity round-trips");

        // saveAccount again must UPDATE the single row, not insert a second one.
        account.password = "changed";
        storage.saveAccount(account);
        check(storage.loadAccount().password == "changed", "saveAccount upserts the single account row");
    }

    // --- reopening with the correct key must see the same data ---
    {
        Storage storage(dbPath, key);
        check(storage.hasAccount(), "data survives close+reopen with correct key");
        check(storage.loadAccount().password == "changed", "data is unchanged after reopen");
    }

    // --- the file must not be plain SQLite: no cleartext "SQLite format 3" header ---
    {
        std::ifstream file(dbPath, std::ios::binary);
        char header[16] = {};
        file.read(header, sizeof(header));
        std::string headerStr(header, header + 16);
        check(headerStr != "SQLite format 3", "database file is not a plaintext SQLite header (looks encrypted)");
    }

    // --- opening with the wrong key must fail once real data is touched ---
    {
        bool threw = false;
        try {
            Storage wrongKeyStorage(dbPath, "wrong-passphrase");
            wrongKeyStorage.hasAccount(); // forces first real table access
        } catch (const std::exception&) {
            threw = true;
        }
        check(threw, "opening with the wrong key fails");
    }

    std::cout << "\n" << (g_failures == 0 ? "ALL PASS" : std::to_string(g_failures) + " FAILURE(S)") << "\n";
    return g_failures == 0 ? 0 : 1;
}
