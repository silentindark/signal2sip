#pragma once

// The ECIES-style construction used only for Flow B's QR-pairing
// handshake (NOT a Signal Protocol/Double-Ratchet session) - C++ port of
// layer1/provisioningCipher.js's decrypt(), matching PROTOCOL.md's
// "Provisioning cipher" writeup exactly: X25519 ECDH -> HKDF-SHA256
// (info="TextSecure Provisioning Message") -> AES-256-CBC + HMAC-SHA256.
//
// libsignal's FFI exposes X25519 agree (signal_privatekey_agree) and HKDF
// (signal_hkdf_derive) but no generic AES-CBC/HMAC - those two primitives
// come straight from OpenSSL's libcrypto here, a dependency isolated to
// this one file.

#include "../storage/Storage.h"

namespace signal2sip {

// Decrypts a real ProvisionEnvelope's {publicKey, body} fields using
// `ourPrivateKey` (the ephemeral keypair whose public half was embedded in
// the sgnl://linkdevice URL a primary device scanned). Returns the
// plaintext, serialized ProvisionMessage. Throws std::runtime_error on any
// validation failure (bad version byte, MAC mismatch, truncated body).
Bytes decryptProvisionEnvelope(const Bytes& ourPrivateKey, const Bytes& envelopePublicKey, const Bytes& envelopeBody);

} // namespace signal2sip
