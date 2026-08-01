#pragma once

// Milestone G: bidirectional bridge between real Signal CallMessage
// protobufs (SignalService.proto) and RingRTC's C ABI
// (native/ringrtc/signal2sip_ringrtc.h) - C++ port of
// layer1/callBridge.js's callingMessageToProtoFields()/
// protoCallMessageToCallingMessage()/onContent(), now driving the real
// RingRTC CallManager instead of libringrtc's Node bindings.

#include <cstdint>
#include <string>

#include "../ringrtc/signal2sip_ringrtc.h"
#include "../signal/AuthSocket.h"
#include "../signal/Crypto.h"
#include "../signal/ProtocolStores.h"
#include "../storage/Storage.h"
#include "SignalService.pb.h"

namespace signal2sip {

// Strips libsignal's serialize() leading type byte (33 bytes -> 32 raw
// Curve25519 key bytes) - RingRTC's SRTP key derivation needs the raw
// form; see signal2sip_call_received_offer's doc comment in
// signal2sip_ringrtc.h for the real bug this fixes (wrong SRTP keys,
// silent - not an error - if you pass the 33-byte form).
Bytes rawPublicKeyBytes(const Bytes& serialized);

// Receive side: dispatches an already-decrypted Content's callMessage (if
// present - check callMessage.has_offer() etc. first, or just call this
// unconditionally with a default-constructed CallMessage when there's
// nothing to do) into the local CallManagerHandle. `stores` is used to
// look up the sender's and our own identity keys for the Offer case.
void handleCallMessage(Signal2sipCallManagerHandle* handle, ProtocolStores& stores,
                        const std::string& senderServiceId, uint32_t senderDeviceId, uint32_t localDeviceId,
                        const signalservice::CallMessage& callMessage);

// Send side: implements Signal2sipCallbacks' send_offer/send_answer/
// send_ice/send_hangup by building, encrypting, and sending a real
// CallMessage over the given AuthSocket - the mirror image of
// handleCallMessage. `remotePeerId` is always the destination serviceId
// (same string this project's C ABI passes as remote_peer_id
// everywhere). Establishes a session first (fetching a prekey bundle) if
// none exists yet with that peer - same fallback signal_roundtrip_test.cpp
// uses for regular messages.
class CallMessageSender {
public:
    CallMessageSender(AuthSocket& socket, ProtocolStores& stores, std::string localServiceId,
                       uint32_t localDeviceId);

    void sendOffer(const std::string& remotePeerId, uint64_t callId, int32_t mediaType, const uint8_t* opaque,
                    size_t opaqueLen);
    void sendAnswer(const std::string& remotePeerId, uint64_t callId, const uint8_t* opaque, size_t opaqueLen);
    void sendIce(const std::string& remotePeerId, uint64_t callId, bool hasReceiverDeviceId,
                 uint32_t receiverDeviceId, const uint8_t* opaque, size_t opaqueLen);
    void sendHangup(const std::string& remotePeerId, uint64_t callId, int32_t hangupType, uint32_t hangupDeviceId);

private:
    // Ensures a session exists with every (or one specific, if
    // hasReceiverDeviceId) device of remotePeerId, fetching+processing a
    // prekey bundle if needed, then encrypts+sends the given CallMessage
    // to each resulting device. Returns the device ids actually sent to.
    std::vector<int> sendCallMessage(const std::string& remotePeerId, const signalservice::CallMessage& callMessage,
                                      bool hasReceiverDeviceId, uint32_t receiverDeviceId);

    AuthSocket& socket_;
    ProtocolStores& stores_;
    std::string localServiceId_;
    uint32_t localDeviceId_;
};

// Real Signal Protocol session-recovery: call this when an incoming
// identified (DOUBLE_RATCHET/PREKEY_MESSAGE) envelope fails to decrypt -
// tells the sender via a DecryptionErrorMessage reply so its own client
// can detect the desync and re-establish a fresh session on its own,
// instead of failing silently forever (found live: a real phone's
// session with this daemon had drifted from a stale local test fixture,
// and there was no way to recover other than this). `originalCiphertext`/
// `originalType`/`originalTimestamp` must be exactly what came off the
// wire in the envelope that failed - see
// Crypto.h's buildDecryptionErrorPlaintextContent() for why. Best-effort:
// logs and swallows its own failures rather than throwing, since this
// runs from an already-failed decrypt path and shouldn't take down
// anything else.
void sendDecryptionErrorReply(AuthSocket& socket, ProtocolStores& stores, const std::string& localServiceId,
                               uint32_t localDeviceId, const std::string& senderServiceId, uint32_t senderDeviceId,
                               const Bytes& originalCiphertext, uint8_t originalType, uint64_t originalTimestamp);

} // namespace signal2sip
