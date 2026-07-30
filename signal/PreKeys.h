#pragma once

// C++ port of layer1/preKeys.js: builds a signed EC prekey / last-resort
// Kyber prekey, signed by a given identity's private key. Returns both the
// wire-format fields (for the PUT /v2/keys request body) and the full
// serialized Record blob (what Storage's signed_prekey/kyber_prekey.record
// columns hold - the only supported way to reconstruct a working
// SignedPreKeyRecord/KyberPreKeyRecord later, deserializing raw key bytes
// directly does not work for KyberPreKeyRecord).

#include <cstdint>

#include "../storage/Storage.h"

namespace signal2sip {

struct WirePreKey {
    int64_t keyId;
    Bytes publicKey;
    Bytes signature;
};

struct GeneratedSignedPreKey {
    WirePreKey wire;
    SignedPrekeyRecord stored; // full serialized Record, for Storage::saveSignedPrekey
};

struct GeneratedKyberPreKey {
    WirePreKey wire;
    KyberPrekeyRecord stored; // full serialized Record, for Storage::saveKyberPrekey
};

GeneratedSignedPreKey generateSignedPreKey(const Bytes& identityPrivateKey, int64_t keyId);
GeneratedKyberPreKey generateKyberPreKey(const Bytes& identityPrivateKey, int64_t keyId);

} // namespace signal2sip
