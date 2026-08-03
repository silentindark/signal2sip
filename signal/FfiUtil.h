#pragma once

// Small helpers around libsignal's raw C ABI (signal_ffi.h): error
// propagation, owned/borrowed buffer conversion. Every wrapper in this
// directory that calls a `signal_*` function goes through checkError() so a
// SignalFfiError always becomes a thrown std::runtime_error with the
// message libsignal produced, never a silently ignored error code.

#include <signal_ffi.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "../storage/Storage.h"

namespace signal2sip {

// Throws std::runtime_error (freeing `err`) if `err` is non-null; no-op
// otherwise. Call this immediately after every signal_* call.
inline void checkError(SignalFfiError* err) {
    if (!err) return;
    SignalCStringPtr message = nullptr;
    SignalFfiError* messageErr = signal_error_get_message(&message, err);
    std::string what = "libsignal error (failed to retrieve message)";
    if (!messageErr && message) {
        what = reinterpret_cast<const char*>(message);
        signal_free_string(message);
    } else if (messageErr) {
        signal_error_free(messageErr);
    }
    signal_error_free(err);
    throw std::runtime_error(what);
}

inline SignalBorrowedBuffer borrow(const Bytes& data) {
    return SignalBorrowedBuffer{data.data(), data.size()};
}

// Copies an owned buffer's contents out and frees it - never hold onto the
// raw pointer past this call.
inline Bytes takeOwned(SignalOwnedBuffer& buffer) {
    Bytes result(buffer.base, buffer.base + buffer.length);
    signal_free_buffer(buffer.base, buffer.length);
    return result;
}

inline SignalMutPointerPublicKey publicKeyDeserialize(const Bytes& data) {
    SignalMutPointerPublicKey key{};
    checkError(signal_publickey_deserialize(&key, borrow(data)));
    return key;
}

inline SignalMutPointerPrivateKey privateKeyDeserialize(const Bytes& data) {
    SignalMutPointerPrivateKey key{};
    checkError(signal_privatekey_deserialize(&key, borrow(data)));
    return key;
}

// Serializes and destroys an owned public key handle in one step - used on
// every callback argument we're handed (we don't keep long-lived handles).
inline Bytes publicKeySerializeAndDestroy(SignalMutPointerPublicKey key) {
    SignalOwnedBuffer buffer{};
    checkError(signal_publickey_serialize(&buffer, SignalConstPointerPublicKey{key.raw}));
    Bytes bytes = takeOwned(buffer);
    checkError(signal_publickey_destroy(key));
    return bytes;
}

// Reads "<name>.<deviceId>" from an owned address handle and destroys it -
// matches FileSessionStore's ProtocolAddress::toString() key format.
inline std::string addressKeyAndDestroy(SignalMutPointerProtocolAddress address) {
    SignalConstPointerProtocolAddress constAddress{address.raw};
    SignalCStringPtr name = nullptr;
    checkError(signal_address_get_name(&name, constAddress));
    uint32_t deviceId = 0;
    checkError(signal_address_get_device_id(&deviceId, constAddress));
    std::string result = std::string(reinterpret_cast<const char*>(name)) + "." + std::to_string(deviceId);
    signal_free_string(name);
    checkError(signal_address_destroy(address));
    return result;
}

struct KeyPair {
    Bytes privateKey;
    Bytes publicKey;
};

// Generates a fresh X25519 keypair - a new account's identity keys (Flow
// A/B in gendb), or an ephemeral keypair for the provisioning cipher's
// ECDH step (Flow B) - same signal_privatekey_generate/get_public_key/
// serialize sequence PreKeys.cpp already uses for prekey generation.
inline KeyPair generateKeyPair() {
    SignalMutPointerPrivateKey priv{};
    checkError(signal_privatekey_generate(&priv));
    SignalOwnedBuffer privBuffer{};
    checkError(signal_privatekey_serialize(&privBuffer, SignalConstPointerPrivateKey{priv.raw}));
    Bytes privBytes = takeOwned(privBuffer);

    SignalMutPointerPublicKey pub{};
    checkError(signal_privatekey_get_public_key(&pub, SignalConstPointerPrivateKey{priv.raw}));
    Bytes pubBytes = publicKeySerializeAndDestroy(pub);

    checkError(signal_privatekey_destroy(priv));
    return KeyPair{privBytes, pubBytes};
}

inline SignalMutPointerProtocolAddress addressNew(const std::string& serviceId, uint32_t deviceId) {
    SignalMutPointerProtocolAddress addr{};
    checkError(signal_address_new(&addr, reinterpret_cast<const int8_t*>(serviceId.c_str()), deviceId));
    return addr;
}

// Modern chat.signal.org envelopes carry the sender/destination identity as
// the fixed-width binary ServiceId encoding (Envelope.sourceServiceIdBinary/
// destinationServiceIdBinary - 1 type byte + 16 UUID bytes), not the legacy
// plain-UUID string field (Envelope.sourceServiceId/destinationServiceId,
// left empty by the real server) - matches layer1/flowc-receive.js's
// resolveServiceId()/Aci.parseFromServiceIdBinary(), just via the raw C ABI
// instead of the Node bindings. Returns "" for an empty/missing binary field.
inline std::string resolveServiceId(const std::string& binary) {
    if (binary.empty()) return "";
    Bytes bytes(binary.begin(), binary.end());
    SignalType_FixedArray17_uint8_t normalized{};
    checkError(signal_service_id_parse_from_service_id_binary(&normalized, borrow(bytes)));
    SignalCStringPtr str = nullptr;
    checkError(signal_service_id_service_id_string(&str, &normalized));
    std::string result(reinterpret_cast<const char*>(str));
    signal_free_string(str);
    return result;
}

} // namespace signal2sip
