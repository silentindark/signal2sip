#pragma once

// High-level Signal Protocol operations built on top of ProtocolStores -
// C++ port of what layer1/sendMessage.js, layer1/preKeyBundle.js, and
// layer1/flowc-receive.js do with @signalapp/libsignal-client, now against
// the real signal_ffi.h C ABI + SQLCipher-backed ProtocolStores.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "ProtocolStores.h"
#include "../storage/Storage.h"

namespace signal2sip {

// A libsignal ProtocolAddress's two fields - a bare serviceId (no ".device"
// suffix; that suffix is Storage's own key-format convention, not part of
// the FFI's actual signal_address_new(name, device_id) call) and a real
// device id.
struct Address {
    std::string serviceId;
    uint32_t deviceId;
};

struct RemotePreKeyBundle {
    std::string serviceId;
    uint32_t deviceId;
    uint32_t registrationId;
    std::optional<uint32_t> preKeyId;
    std::optional<Bytes> preKeyPublic;
    uint32_t signedPreKeyId;
    Bytes signedPreKeyPublic;
    Bytes signedPreKeySignature;
    Bytes identityKey;
    uint32_t kyberPreKeyId;
    Bytes kyberPreKeyPublic;
    Bytes kyberPreKeySignature;
};

// Establishes (or re-establishes) a session with one remote device from a
// fetched pre-key bundle - mirrors preKeyBundle.js's per-device
// processPreKeyBundle() call.
void establishSession(ProtocolStores& stores, const Address& localAddress, const RemotePreKeyBundle& bundle);

// Pads and encrypts one message for one already-sessioned device -
// mirrors sendMessage.js's encryptForDevice(). Returns the serialized
// ciphertext plus its libsignal message type (needed for the envelope's
// type field), matching layer1/sendMessage.js's shape.
struct EncryptedMessage {
    Bytes ciphertext;
    uint8_t type; // CiphertextMessageType, from signal_ciphertext_message_type
};
EncryptedMessage encryptForDevice(ProtocolStores& stores, const Address& localAddress, const Address& remoteAddress,
                                  const Bytes& plaintextContent);

// Decrypts one already-unwrapped (non-sealed-sender) envelope's ciphertext,
// dispatching on whether it's a PreKeySignalMessage (type 3) or a plain
// SignalMessage (type 2) - matches flowc-receive.js's ENVELOPE_TYPE
// handling for CIPHERTEXT/PREKEY_BUNDLE envelopes. Returns the
// padding-stripped plaintext.
Bytes decryptCiphertext(ProtocolStores& stores, const Address& localAddress, const Address& remoteAddress,
                         uint8_t messageType, const Bytes& ciphertext);

struct SealedSenderResult {
    std::string senderServiceId;
    uint32_t senderDeviceId;
    Bytes plaintext; // padding-stripped
};
// Decrypts a sealed-sender (UNIDENTIFIED_SENDER) envelope's ciphertext,
// recovering the real sender identity from the embedded sender
// certificate before dispatching to the same decrypt path as
// decryptCiphertext() - matches flowc-receive.js's sealed-sender handling.
SealedSenderResult decryptSealedSender(ProtocolStores& stores, const Address& localAddress,
                                       const Bytes& sealedSenderCiphertext, uint64_t serverTimestamp);

} // namespace signal2sip
