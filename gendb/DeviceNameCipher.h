#pragma once

// Encrypts a plaintext device name for the `accountAttributes.name` field
// of PUT /v1/devices/link (Flow B) - without this, the linked device shows
// up as "Unnamed device" in the real Signal app's Linked Devices list
// (see project notes: signal2sip previously sent a hard-coded null here).
// C++ port of libsignal-service-java's DeviceNameUtil.encryptDeviceName():
// X25519 ECDH (identity private key + a fresh ephemeral public key) ->
// double HMAC-SHA256 derivation (a synthetic/deterministic IV derived from
// the plaintext itself, then a cipher key derived from that IV) ->
// AES-256-CTR with a zero IV (safe here because the cipher key is already
// unique per plaintext via the synthetic-IV chain) -> DeviceName proto,
// base64-encoded WITH padding (unlike base64NoPadding used elsewhere in
// gendb).
//
// Reuses the same X25519-agree/HMAC-SHA256 primitives ProvisioningCipher.cpp
// already wraps, just a different construction (CTR not CBC, no HKDF).

#include "../storage/Storage.h"

namespace signal2sip {

// `aciIdentityPrivateKey` is the account's ACI identity private key (the
// same one just received via ProvisionMessage during linking - shared
// across every device on the account, not per-device). Returns the
// base64(-with-padding) string ready to place directly in
// accountAttributes.name.
std::string encryptDeviceName(const std::string& plaintextDeviceName, const Bytes& aciIdentityPrivateKey);

} // namespace signal2sip
