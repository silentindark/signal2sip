#pragma once

// Shared tail of both Flow A (register-verify.js) and Flow B
// (link-new-device.js): once the server has confirmed a new account/device
// (real uuid/pni/deviceId in hand) and we have ACI+PNI identity keypairs
// (freshly generated for Flow A, taken from the decrypted ProvisionMessage
// for Flow B), build signed+Kyber prekeys and persist everything via
// Storage - the same four calls main.cpp's migrateFromNodePrototype()
// already makes for the two Node-prototype accounts, just with
// freshly-generated data instead of imported JSON.

#include <cstdint>
#include <optional>
#include <string>

#include "../signal/FfiUtil.h"
#include "../signal/PreKeys.h"
#include "../storage/Storage.h"

namespace signal2sip {

// crypto.randomInt(1, 16384) equivalent - registrationId/pniRegistrationId.
int64_t randomRegistrationId();

struct GeneratedPrekeys {
    GeneratedSignedPreKey aciSignedPreKey;
    GeneratedSignedPreKey pniSignedPreKey;
    GeneratedKyberPreKey aciKyberPreKey;
    GeneratedKyberPreKey pniKyberPreKey;
};

// keyId defaults to 1, matching both Node flows (buildSignedPreKey/
// buildKyberPreKey's own default - a brand-new account's very first
// prekey).
GeneratedPrekeys generatePrekeys(const Bytes& aciPrivateKey, const Bytes& pniPrivateKey, int64_t keyId = 1);

struct FinishedAccount {
    std::string e164, aci, pni, password;
    int deviceId = 1;
    int64_t registrationId = 0;
    int64_t pniRegistrationId = 0;
    KeyPair aciIdentity;
    KeyPair pniIdentity;
    GeneratedPrekeys prekeys;
    std::string flow; // "standalone" | "linked"
    std::optional<std::string> accountEntropyPool;   // linked accounts only
    std::optional<Bytes> mediaRootBackupKey;         // linked accounts only
    std::optional<Bytes> profileKey;                 // linked accounts only
};

// Writes account/identity_keypair/signed_prekey/kyber_prekey rows -
// storage must already be scoped to the right account_name (the
// [account.<name>] this gendb invocation targets).
void saveFinishedAccount(Storage& storage, const FinishedAccount& account);

} // namespace signal2sip
