#include "StorageServiceSync.h"

#include <cstdio>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <nlohmann/json.hpp>

#include "StorageService.pb.h"
#include "../signal/FfiUtil.h"
#include "../util/Base64.h"
#include "../util/RegistrationClient.h"

using json = nlohmann::json;

namespace signal2sip {

namespace {

// Not chat.signal.org - storage.signal.org is a genuinely separate host
// (SignalServiceNetworkAccess.kt's signalStorageUrls), plain REST + Basic
// auth, unlike the persistent-websocket AuthSocket every other Signal-
// Server call in this project uses. Only the initial GET /v1/storage/auth
// token fetch happens over the normal AuthSocket - see fetchStorageContacts().
constexpr const char* kStorageHost = "storage.signal.org";

Bytes hmacSha256(const Bytes& key, const std::string& data) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
              reinterpret_cast<const unsigned char*>(data.data()), data.size(), out, &outLen)) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }
    return Bytes(out, out + outLen);
}

// Every StorageService manifest/item value is
// AES-256-GCM(iv(12 bytes) || ciphertext || tag(16 bytes, GCM-appended)) -
// mirrors SignalStorageCipher.kt (Signal-Android) exactly, the reference
// implementation for this scheme.
Bytes aesGcmDecrypt(const Bytes& key, const Bytes& ivCiphertextTag) {
    constexpr size_t kIvLen = 12;
    constexpr size_t kTagLen = 16;
    if (ivCiphertextTag.size() < kIvLen + kTagLen) {
        throw std::runtime_error("storage record too short to be a valid AES-GCM blob");
    }
    const uint8_t* iv = ivCiphertextTag.data();
    const uint8_t* ciphertext = ivCiphertextTag.data() + kIvLen;
    size_t ciphertextLen = ivCiphertextTag.size() - kIvLen - kTagLen;
    auto* tag = const_cast<uint8_t*>(ivCiphertextTag.data() + kIvLen + ciphertextLen);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    Bytes plaintext(ciphertextLen);
    int len = 0;
    int plaintextLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvLen), nullptr) == 1;
    ok = ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) == 1;
    ok = ok && EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, static_cast<int>(ciphertextLen)) == 1;
    if (ok) plaintextLen = len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen), tag) == 1;
    ok = ok && EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLen, &len) == 1;
    if (ok) plaintextLen += len;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("storage record AES-256-GCM decrypt/auth failed (wrong key, or tampered)");
    plaintext.resize(plaintextLen);
    return plaintext;
}

// account_entropy_pool -> svr_key -> storage_service_key, entirely local
// (StorageKey.kt's own doc comment: "Created via MasterKey.deriveStorageServiceKey"
// - accountEntropyPoolDeriveSvrKey + svrKeyDeriveStorageServiceKey is this
// project's equivalent chain using libsignal-ffi's own primitives, no
// SVR/PIN network round-trip needed since we already have the entropy pool
// itself, captured at registration/link time - see AccountRecord::account_entropy_pool).
Bytes deriveStorageServiceKey(const std::string& accountEntropyPool) {
    uint8_t svrKey[32];
    checkError(signal_account_entropy_pool_derive_svr_key(
        &svrKey, reinterpret_cast<const int8_t*>(accountEntropyPool.c_str())));
    uint8_t storageKey[32];
    checkError(signal_svr_key_derive_storage_service_key(&storageKey, &svrKey));
    return Bytes(storageKey, storageKey + 32);
}

// StorageKey.kt: deriveManifestKey(version) = HMAC-SHA256(key, "Manifest_$version").
Bytes deriveManifestKey(const Bytes& storageServiceKey, uint64_t version) {
    return hmacSha256(storageServiceKey, "Manifest_" + std::to_string(version));
}

// StorageKey.kt: deriveItemKey(rawId) = HMAC-SHA256(key, "Item_" + base64(rawId))
// - standard padded base64 (Base64.encodeWithPadding), matches this
// project's own base64Encode().
Bytes deriveItemKey(const Bytes& storageServiceKey, const Bytes& rawId) {
    return hmacSha256(storageServiceKey, "Item_" + base64Encode(rawId));
}

} // namespace

std::vector<StorageContact> fetchStorageContacts(AuthSocket& socket, const std::string& accountEntropyPool) {
    // Every step of this derivation chain (AEP->svrKey HKDF-SHA256, svrKey->
    // storageServiceKey HMAC-SHA256, and this file's own AES-256-GCM decrypt)
    // was independently verified live 2026-08-05 against known-answer test
    // vectors (libsignal's own rust/account-keys/src/lib.rs::svr_key_tests,
    // an independently Python-computed HKDF vector, and a standard AES-GCM
    // vector) - all matched exactly, and this account's own stored AEP
    // passes signal_account_entropy_pool_is_valid(). Yet the real manifest
    // still fails to decrypt for account 123456789002 specifically (a
    // year-plus-old account, linked via gendb) - most likely explanation:
    // this account predates the AEP-based key-derivation scheme entirely
    // (the HKDF info string is literally "20240801_SIGNAL_SVR_MASTER_KEY",
    // i.e. introduced 2024-08-01) and its real storage service key still
    // comes from an old, separately-stored/PIN-recovered "master key" that
    // was never migrated to be AEP-derivable, or our own gendb link flow
    // never captured that legacy key at all (only ever captures
    // accountEntropyPool - see AccountFinisher.cpp). Not yet resolved -
    // see project memory for the current status before extending this.
    if (accountEntropyPool.empty()) {
        throw std::runtime_error("no account_entropy_pool stored for this account - cannot derive storage key");
    }
    Bytes storageServiceKey = deriveStorageServiceKey(accountEntropyPool);

    AuthSocket::Response authResp = socket.request("GET", "/v1/storage/auth");
    if (authResp.status != 200) {
        throw std::runtime_error("GET /v1/storage/auth -> status " + std::to_string(authResp.status));
    }
    json authJson = json::parse(std::string(authResp.body.begin(), authResp.body.end()));
    std::string username = authJson.at("username").get<std::string>();
    std::string password = authJson.at("password").get<std::string>();

    RegistrationClient storageClient(kStorageHost);

    HttpResponse manifestResp = storageClient.request("GET", "/v1/storage/manifest", "", username, password);
    if (manifestResp.status != 200) {
        throw std::runtime_error("GET /v1/storage/manifest -> status " + std::to_string(manifestResp.status));
    }
    signalservice::StorageManifest manifest;
    if (!manifest.ParseFromString(manifestResp.body)) {
        throw std::runtime_error("failed to parse StorageManifest protobuf");
    }

    std::cerr << "[storage-sync-debug] manifestRespBodyLen=" << manifestResp.body.size()
               << " manifest.version=" << manifest.version() << " manifest.value.size=" << manifest.value().size()
               << "\n";

    Bytes manifestKey = deriveManifestKey(storageServiceKey, manifest.version());
    Bytes manifestPlaintext =
        aesGcmDecrypt(manifestKey, Bytes(manifest.value().begin(), manifest.value().end()));

    signalservice::ManifestRecord manifestRecord;
    if (!manifestRecord.ParseFromArray(manifestPlaintext.data(), static_cast<int>(manifestPlaintext.size()))) {
        throw std::runtime_error("failed to parse ManifestRecord protobuf");
    }

    // Only CONTACT-type identifiers - see StorageService.proto's own doc
    // comment for why every other record type (groups, account settings,
    // stickers, ...) is deliberately never even fetched.
    signalservice::ReadOperation readOp;
    for (const auto& identifier : manifestRecord.identifiers()) {
        if (identifier.type() == signalservice::ManifestRecord_Identifier_Type_CONTACT) {
            readOp.add_readkey(identifier.raw());
        }
    }
    if (readOp.readkey_size() == 0) return {};

    std::string readOpBytes;
    readOp.SerializeToString(&readOpBytes);
    HttpResponse itemsResp = storageClient.requestRaw("PUT", "/v1/storage/read", readOpBytes,
                                                       "application/x-protobuf", username, password);
    if (itemsResp.status != 200) {
        throw std::runtime_error("PUT /v1/storage/read -> status " + std::to_string(itemsResp.status));
    }
    signalservice::StorageItems items;
    if (!items.ParseFromString(itemsResp.body)) {
        throw std::runtime_error("failed to parse StorageItems protobuf");
    }

    std::vector<StorageContact> contacts;
    for (const auto& item : items.items()) {
        Bytes rawId(item.key().begin(), item.key().end());
        Bytes itemKey = deriveItemKey(storageServiceKey, rawId);
        Bytes itemPlaintext = aesGcmDecrypt(itemKey, Bytes(item.value().begin(), item.value().end()));

        signalservice::StorageRecord record;
        if (!record.ParseFromArray(itemPlaintext.data(), static_cast<int>(itemPlaintext.size()))) continue;
        if (!record.has_contact()) continue;

        const auto& c = record.contact();
        StorageContact contact;
        contact.aci = c.aci();
        contact.pni = c.pni();
        contact.e164 = c.e164();
        contact.profileKey.assign(c.profilekey().begin(), c.profilekey().end());
        contacts.push_back(std::move(contact));
    }
    return contacts;
}

} // namespace signal2sip
