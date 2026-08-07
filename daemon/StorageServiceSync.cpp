#include "StorageServiceSync.h"

#include <cstdio>
#include <iostream>
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

// Legacy path (StorageKey.kt: deriveItemKey(rawId) = HMAC-SHA256(key,
// "Item_" + base64(rawId)), standard padded base64) - only correct when
// the manifest has no recordIkm (see deriveItemKeyFromRecordIkm below,
// the modern/default path for any account with SSRE2 record-IKM support -
// which covers every item in this project's own real test account, so
// this legacy path is effectively dead code for us but kept as the
// documented fallback real Signal-Android/iOS also keep).
Bytes deriveItemKey(const Bytes& storageServiceKey, const Bytes& rawId) {
    return hmacSha256(storageServiceKey, "Item_" + base64Encode(rawId));
}

// RecordIkm.kt: deriveStorageItemKey(rawId) = HKDF-SHA256(ikm=recordIkm,
// salt=empty, info="20240801_SIGNAL_STORAGE_SERVICE_ITEM_" + rawId (raw
// bytes, NOT base64 - unlike the legacy HMAC path above), outputLength=32).
// recordIkm comes from ManifestRecord.recordIkm - present whenever the
// account has the modern SSRE2 record-IKM feature, which per real
// Signal-Android's StorageSyncJob.kt log message ("SSRE2 capability is
// supported, but no recordIkm is set") is the expected default for
// current accounts - confirmed 2026-08-06 to be exactly why this
// project's own item decrypts were failing 72/72: this file was only
// ever implementing the legacy path.
// ContactRecord.aci/pni (StorageService.proto fields 1/15, plain string
// UUID) are the legacy representation - real, current Signal-Android
// writes the 16-byte binary aciBinary/pniBinary (fields 25/26) instead,
// leaving the string fields empty. Found live 2026-08-06: a real,
// long-established mutual contact (both directions, years of real
// messages/calls) came back with an empty aci from this file's own
// c.aci() read, breaking ContactResolver's ACI-preferred lookup and
// silently falling all the way back to the CDS/PNI cold-call path for a
// contact that should never have needed it - same root cause class as
// this project's other legacy-string-field-vs-binary-field bugs (see
// FfiUtil.h's resolveServiceId() for the analogous Envelope field, and
// the PNI: prefix fix in this daemon's outgoing-call resolution).
std::string uuidBytesToStringOrEmpty(const std::string& bytes) {
    if (bytes.size() != 16) return "";
    const auto* b = reinterpret_cast<const uint8_t*>(bytes.data());
    char buf[37];
    std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0],
                  b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return buf;
}

Bytes deriveItemKeyFromRecordIkm(const Bytes& recordIkm, const Bytes& rawId) {
    static const std::string kInfoPrefix = "20240801_SIGNAL_STORAGE_SERVICE_ITEM_";
    Bytes info(kInfoPrefix.begin(), kInfoPrefix.end());
    info.insert(info.end(), rawId.begin(), rawId.end());
    Bytes out(32);
    checkError(signal_hkdf_derive(borrowMutable(out), borrow(recordIkm), borrow(info), SignalBorrowedBuffer{nullptr, 0}));
    return out;
}

} // namespace

std::vector<StorageContact> fetchStorageContacts(AuthSocket& socket, const std::string& accountEntropyPool) {
    // The "legacy pre-AEP master key" theory this comment used to describe
    // is DISPROVEN as of 2026-08-06: a real Desktop client linked to this
    // same account (123456789002) a month before this account_entropy_pool
    // was captured, and synced its contact list correctly - so whatever
    // key that Desktop client used was already AEP-derived by then, and a
    // fresh SyncMessage.Keys round-trip against the live primary returned
    // the exact same 64-char AEP we already had (byte-for-byte) - not stale.
    //
    // RESOLVED 2026-08-06: the manifest decrypt's real non-determinism
    // (byte-identical key+ciphertext sometimes decrypting, sometimes not,
    // within this process, while a standalone Python decrypt of the exact
    // same captured bytes succeeded 5/5 outside it) was this project's
    // third instance of the libsrtp-collision bug class (see
    // tools/isolate_webrtc_boringssl_symbols.py's docstring): both
    // ringrtc/webrtc's prebuilt libwebrtc.a AND libsignal_ffi.a (via
    // aws-lc-rs) statically vendor their own BoringSSL-family copy of the
    // plain-C OpenSSL EVP API, and one of them was silently winning link-
    // time symbol resolution over system libcrypto.so.3 for exactly the
    // EVP_aes_256_gcm/EVP_CIPHER_CTX_*/EVP_Decrypt* symbols this file
    // calls - confirmed via `nm -D` on the built daemon (these symbols
    // were entirely absent from the dynamic-undefined list, i.e. never
    // going to be satisfied by libcrypto.so.3 at runtime) and via `nm` on
    // the vendored archives (both had their own global, non-namespaced
    // definitions). Isolating both archives' BoringSSL-family symbols the
    // same way libsrtp's were isolated fixed it - manifest decrypt is now
    // 100% reliable (verified via native/test/storage_sync_loop_test.cpp,
    // 20/20 real fetches, plus step-by-step EVP call tracing and a
    // dladdr() check confirming every call now genuinely resolves to
    // libcrypto.so.3).
    //
    // Separately, RESOLVED 2026-08-06: every one of this account's ~72
    // CONTACT item records failed to decrypt under deriveItemKey()
    // (legacy HMAC path), independent of the fix above - the formula and
    // storageServiceKey were both independently proven correct (a
    // "storageServiceKey rotated, old records never rewritten" theory
    // didn't hold up either: a real Desktop client linked to this same
    // account ~1 month before this AEP was captured synced its contact
    // list correctly immediately, and SyncMessage.Keys confirms our AEP
    // is still byte-identical to the primary's current one - no rotation
    // in between). Real cause found by checking Signal-Android/iOS source
    // directly: modern accounts with the SSRE2 "record IKM" feature
    // (RecordIkm.kt, real Signal-Android's StorageSyncJob.kt logs "SSRE2
    // capability is supported, but no recordIkm is set" as a warning,
    // implying it's the expected default) encrypt every item under a key
    // derived via HKDF from ManifestRecord.recordIkm, NOT the legacy
    // HMAC-from-storageServiceKey path - this file only ever implemented
    // the legacy path. See deriveItemKeyFromRecordIkm() below - confirmed
    // fixed live, all 72 items now decrypt.
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

    Bytes recordIkm(manifestRecord.recordikm().begin(), manifestRecord.recordikm().end());

    std::vector<StorageContact> contacts;
    int skipped = 0;
    for (const auto& item : items.items()) {
        Bytes rawId(item.key().begin(), item.key().end());
        Bytes itemKey = recordIkm.empty() ? deriveItemKey(storageServiceKey, rawId)
                                           : deriveItemKeyFromRecordIkm(recordIkm, rawId);
        Bytes itemPlaintext;
        try {
            itemPlaintext = aesGcmDecrypt(itemKey, Bytes(item.value().begin(), item.value().end()));
        } catch (const std::exception&) {
            // Shouldn't normally happen now that both the manifest-decrypt
            // and item-key-derivation bugs are fixed (see this function's
            // own doc comment) - kept as a defensive skip-and-continue,
            // matching real Signal client behavior, in case a genuinely
            // corrupt/edge-case record ever shows up. One bad record
            // shouldn't fail the whole sync.
            skipped++;
            continue;
        }

        signalservice::StorageRecord record;
        if (!record.ParseFromArray(itemPlaintext.data(), static_cast<int>(itemPlaintext.size()))) continue;
        if (!record.has_contact()) continue;

        const auto& c = record.contact();
        StorageContact contact;
        contact.aci = !c.acibinary().empty() ? uuidBytesToStringOrEmpty(c.acibinary()) : c.aci();
        contact.pni = !c.pnibinary().empty() ? uuidBytesToStringOrEmpty(c.pnibinary()) : c.pni();
        contact.e164 = c.e164();
        contact.profileKey.assign(c.profilekey().begin(), c.profilekey().end());
        // Already plaintext at this point (record was AES-GCM-decrypted
        // above, same as every other ContactRecord field read here) - no
        // separate profile-key decryption needed, unlike e.g. a profile's
        // display-name fetched over GET /v1/profile/{uuid}.
        contact.givenName = c.givenname();
        contact.familyName = c.familyname();
        contacts.push_back(std::move(contact));
    }
    if (skipped > 0) {
        std::cerr << "[storage-sync] " << skipped << " of " << items.items_size()
                   << " contact record(s) could not be decrypted (stale key) - skipped\n";
    }
    return contacts;
}

} // namespace signal2sip
