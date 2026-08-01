#include "CallSignaling.h"

#include <chrono>
#include <iostream>
#include <optional>

#include <nlohmann/json.hpp>

#include "../signal/FfiUtil.h"
#include "../util/Base64.h"

using json = nlohmann::json;

namespace signal2sip {

namespace {

Bytes b64(const json& j, const char* key) {
    return base64Decode(j.at(key).get<std::string>());
}

int64_t nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Same fallback signal_roundtrip_test.cpp uses for regular messages:
// fetch the peer's prekey bundle and establish a session with every
// device it reports (or just `onlyDeviceId`, if given - avoids
// establishing sessions with every linked device of a multi-device
// account when only one is actually needed, e.g. sendDecryptionErrorReply
// only ever needs the one device that sent the undecryptable envelope).
// Returns the resulting device ids.
//
// Deliberately does its network fetch *before* taking stores.mutex(), and
// only holds the lock around the actual session-store writes
// (establishSession()) - see ProtocolStores::mutex()'s doc comment for
// why holding it across blocking I/O is a real, previously-live bug, not
// a hypothetical one.
std::vector<int> fetchAndEstablishSessions(AuthSocket& socket, ProtocolStores& stores,
                                            const std::string& localServiceId, uint32_t localDeviceId,
                                            const std::string& remoteServiceId,
                                            std::optional<uint32_t> onlyDeviceId = std::nullopt) {
    std::string devicePath = onlyDeviceId ? std::to_string(*onlyDeviceId) : "*";
    auto response = socket.request("GET", "/v2/keys/" + remoteServiceId + "/" + devicePath);
    if (response.status != 200) {
        throw std::runtime_error("GET /v2/keys/" + remoteServiceId + "/" + devicePath + " -> " +
                                  std::to_string(response.status));
    }
    json body = json::parse(std::string(response.body.begin(), response.body.end()));
    Bytes identityKey = base64Decode(body.at("identityKey").get<std::string>());

    std::vector<RemotePreKeyBundle> bundles;
    for (const auto& device : body.at("devices")) {
        RemotePreKeyBundle bundle;
        bundle.serviceId = remoteServiceId;
        bundle.deviceId = device.at("deviceId").get<uint32_t>();
        bundle.registrationId = device.at("registrationId").get<uint32_t>();
        if (device.contains("preKey") && !device.at("preKey").is_null()) {
            bundle.preKeyId = device.at("preKey").at("keyId").get<uint32_t>();
            bundle.preKeyPublic = b64(device.at("preKey"), "publicKey");
        }
        const auto& signedPreKey = device.at("signedPreKey");
        bundle.signedPreKeyId = signedPreKey.at("keyId").get<uint32_t>();
        bundle.signedPreKeyPublic = b64(signedPreKey, "publicKey");
        bundle.signedPreKeySignature = b64(signedPreKey, "signature");
        bundle.identityKey = identityKey;
        const auto& pqPreKey = device.at("pqPreKey");
        bundle.kyberPreKeyId = pqPreKey.at("keyId").get<uint32_t>();
        bundle.kyberPreKeyPublic = b64(pqPreKey, "publicKey");
        bundle.kyberPreKeySignature = b64(pqPreKey, "signature");
        bundles.push_back(std::move(bundle));
    }

    Address localAddress{localServiceId, localDeviceId};
    std::vector<int> deviceIds;
    {
        std::lock_guard<std::mutex> lock(stores.mutex());
        for (const auto& bundle : bundles) {
            establishSession(stores, localAddress, bundle);
            deviceIds.push_back(static_cast<int>(bundle.deviceId));
        }
    }
    return deviceIds;
}

// Builds and sends the {destination, timestamp, messages, online, urgent}
// PUT /v1/messages body shared by CallMessageSender::sendCallMessage() and
// sendDecryptionErrorReply() - the only difference between those two call
// sites was this framing, not the framing's contents.
AuthSocket::Response putMessages(AuthSocket& socket, const std::string& destination, const json& messages,
                                  bool online) {
    json requestBody = {
        {"destination", destination}, {"timestamp", nowMs()}, {"messages", messages},
        {"online", online},           {"urgent", true},
    };
    std::string bodyStr = requestBody.dump();
    Bytes bodyBytes(bodyStr.begin(), bodyStr.end());
    return socket.request("PUT", "/v1/messages/" + destination + "?story=false", &bodyBytes);
}

// Mirrors sendMessage.js's encryptForDevice(): destinationRegistrationId
// comes from the session record itself (SessionRecord::remoteRegistrationId()),
// not tracked separately - avoids needing a long-lived per-peer cache in
// the daemon.
uint32_t remoteRegistrationIdFromSession(Storage& storage, const std::string& address) {
    auto record = storage.loadSession(address);
    if (!record) return 0;
    SignalMutPointerSessionRecord session{};
    checkError(signal_session_record_deserialize(&session, borrow(*record)));
    uint32_t registrationId = 0;
    checkError(
        signal_session_record_get_remote_registration_id(&registrationId, SignalConstPointerSessionRecord{session.raw}));
    checkError(signal_session_record_destroy(session));
    return registrationId;
}

} // namespace

Bytes rawPublicKeyBytes(const Bytes& serialized) {
    // libsignal's PublicKey::serialize() prepends a 1-byte key type (0x05
    // for Curve25519) to the 32-byte raw key - confirmed against this
    // project's own account data (33 bytes decoded). RingRTC's SRTP
    // derivation wants the bare 32 bytes.
    if (serialized.size() == 33) return Bytes(serialized.begin() + 1, serialized.end());
    return serialized;
}

void handleCallMessage(Signal2sipCallManagerHandle* handle, ProtocolStores& stores,
                        const std::string& senderServiceId, uint32_t senderDeviceId, uint32_t localDeviceId,
                        const signalservice::CallMessage& callMessage) {
    if (callMessage.has_offer()) {
        const auto& offer = callMessage.offer();

        // Narrow lock around just the storage reads, released before
        // calling into RingRTC below - RingRTC can synchronously call
        // back into onSendAnswer/onSendIce (which take this same mutex
        // themselves, briefly), and std::mutex isn't reentrant.
        Bytes senderIdentityKey(32, 0);
        Bytes receiverIdentityKey(32, 0);
        {
            std::lock_guard<std::mutex> lock(stores.mutex());
            if (auto stored = stores.storage().loadRemoteIdentity(senderServiceId)) {
                senderIdentityKey = rawPublicKeyBytes(*stored);
            }
            if (auto keypair = stores.storage().loadIdentityKeypair(stores.identity())) {
                receiverIdentityKey = rawPublicKeyBytes(keypair->public_key);
            }
        }

        const std::string& opaque = offer.opaque();
        signal2sip_call_received_offer(handle, senderServiceId.c_str(), offer.id(), senderDeviceId, localDeviceId,
                                        reinterpret_cast<const uint8_t*>(opaque.data()), opaque.size(),
                                        senderIdentityKey.data(), receiverIdentityKey.data());
    }
    if (callMessage.has_answer()) {
        const auto& answer = callMessage.answer();

        // Same identity-key requirement and same narrow-lock reasoning as
        // the offer branch above - senderServiceId here is the callee
        // (the answer's originator), so the fetch is the same shape.
        // Found live: this branch used to call
        // signal2sip_call_received_answer() without these at all (that
        // overload didn't even exist), and RingRTC's C ABI silently
        // hardcoded 32 zero bytes on the Rust side - the caller's SRTP
        // key derived wrong while the callee's (which did get real keys
        // via the offer branch) was correct, so only the callee ever
        // reached Connected.
        Bytes senderIdentityKey(32, 0);
        Bytes receiverIdentityKey(32, 0);
        {
            std::lock_guard<std::mutex> lock(stores.mutex());
            if (auto stored = stores.storage().loadRemoteIdentity(senderServiceId)) {
                senderIdentityKey = rawPublicKeyBytes(*stored);
            }
            if (auto keypair = stores.storage().loadIdentityKeypair(stores.identity())) {
                receiverIdentityKey = rawPublicKeyBytes(keypair->public_key);
            }
        }

        const std::string& opaque = answer.opaque();
        signal2sip_call_received_answer(handle, senderServiceId.c_str(), answer.id(), senderDeviceId,
                                         reinterpret_cast<const uint8_t*>(opaque.data()), opaque.size(),
                                         senderIdentityKey.data(), receiverIdentityKey.data());
    }
    for (const auto& ice : callMessage.iceupdate()) {
        const std::string& opaque = ice.opaque();
        signal2sip_call_received_ice(handle, senderServiceId.c_str(), ice.id(), senderDeviceId,
                                      reinterpret_cast<const uint8_t*>(opaque.data()), opaque.size());
    }
    if (callMessage.has_hangup()) {
        const auto& hangup = callMessage.hangup();
        signal2sip_call_received_hangup(handle, senderServiceId.c_str(), hangup.id(), senderDeviceId,
                                         static_cast<int32_t>(hangup.type()), hangup.deviceid());
    }
    if (callMessage.has_busy()) {
        signal2sip_call_received_busy(handle, senderServiceId.c_str(), callMessage.busy().id(), senderDeviceId);
    }
}

CallMessageSender::CallMessageSender(AuthSocket& socket, ProtocolStores& stores, std::string localServiceId,
                                       uint32_t localDeviceId)
    : socket_(socket), stores_(stores), localServiceId_(std::move(localServiceId)), localDeviceId_(localDeviceId) {}

std::vector<int> CallMessageSender::sendCallMessage(const std::string& remotePeerId,
                                                      const signalservice::CallMessage& callMessage,
                                                      bool hasReceiverDeviceId, uint32_t receiverDeviceId) {
    std::vector<int> deviceIds;
    bool needSessions;
    {
        std::lock_guard<std::mutex> lock(stores_.mutex());
        if (hasReceiverDeviceId) {
            deviceIds.push_back(static_cast<int>(receiverDeviceId));
            std::string address = remotePeerId + "." + std::to_string(receiverDeviceId);
            needSessions = !stores_.storage().loadSession(address);
        } else {
            deviceIds = stores_.storage().knownDeviceIdsFor(remotePeerId);
            needSessions = deviceIds.empty();
        }
    }
    if (needSessions) {
        // Network I/O - deliberately outside the lock (see
        // fetchAndEstablishSessions()'s own doc comment); it takes the
        // lock itself, briefly, only around the session-store write.
        auto established = fetchAndEstablishSessions(socket_, stores_, localServiceId_, localDeviceId_, remotePeerId,
                                                       hasReceiverDeviceId ? std::optional<uint32_t>(receiverDeviceId)
                                                                            : std::nullopt);
        if (!hasReceiverDeviceId) deviceIds = established;
    }
    if (deviceIds.empty()) return deviceIds;

    signalservice::Content content;
    *content.mutable_callmessage() = callMessage;
    std::string contentBytes;
    content.SerializeToString(&contentBytes);
    Bytes plaintext(contentBytes.begin(), contentBytes.end());

    Address localAddress{localServiceId_, localDeviceId_};
    json messages = json::array();
    {
        // Serialize against every other encrypt/decrypt through this
        // account's session store (concurrent sends, or a send racing
        // the websocket thread's decrypt of an incoming envelope, can
        // otherwise interleave Double Ratchet chain updates - see
        // ProtocolStores::mutex()). Never held across the network PUT
        // below - doing so previously reintroduced the exact
        // self-deadlock class the CallMessage-handling dispatch (see
        // main.cpp's onPush()) was written to avoid, since AuthSocket's
        // single service thread can only ever deliver that PUT's
        // response by running lws_service() again, which it can't do
        // while blocked trying to acquire this same lock for an
        // unrelated incoming envelope.
        std::lock_guard<std::mutex> lock(stores_.mutex());
        for (int deviceId : deviceIds) {
            EncryptedMessage encrypted = encryptForDevice(
                stores_, localAddress, Address{remotePeerId, static_cast<uint32_t>(deviceId)}, plaintext);
            int envelopeType = encrypted.type == SignalCiphertextMessageTypePreKey ? 3 : 1;
            std::string address = remotePeerId + "." + std::to_string(deviceId);
            messages.push_back(
                {{"type", envelopeType},
                 {"destinationDeviceId", deviceId},
                 {"destinationRegistrationId", remoteRegistrationIdFromSession(stores_.storage(), address)},
                 {"content", base64Encode(encrypted.ciphertext)}});
        }
    }

    auto response = putMessages(socket_, remotePeerId, messages, /*online=*/true);
    if (response.status / 100 != 2) {
        std::cerr << "[daemon] PUT /v1/messages/" << remotePeerId << " -> " << response.status << " (body: "
                   << std::string(response.body.begin(), response.body.end()) << ")\n";
    } else {
        std::cout << "[daemon] PUT /v1/messages/" << remotePeerId << " -> " << response.status << " ("
                   << deviceIds.size() << " device(s))\n";
    }
    return deviceIds;
}

void CallMessageSender::sendOffer(const std::string& remotePeerId, uint64_t callId, int32_t mediaType,
                                    const uint8_t* opaque, size_t opaqueLen) {
    signalservice::CallMessage callMessage;
    auto* offer = callMessage.mutable_offer();
    offer->set_id(callId);
    offer->set_type(mediaType == 1 ? signalservice::CallMessage_Offer_Type_OFFER_VIDEO_CALL
                                    : signalservice::CallMessage_Offer_Type_OFFER_AUDIO_CALL);
    offer->set_opaque(opaque, opaqueLen);
    sendCallMessage(remotePeerId, callMessage, false, 0);
}

void CallMessageSender::sendAnswer(const std::string& remotePeerId, uint64_t callId, const uint8_t* opaque,
                                     size_t opaqueLen) {
    signalservice::CallMessage callMessage;
    auto* answer = callMessage.mutable_answer();
    answer->set_id(callId);
    answer->set_opaque(opaque, opaqueLen);
    sendCallMessage(remotePeerId, callMessage, false, 0);
}

void CallMessageSender::sendIce(const std::string& remotePeerId, uint64_t callId, bool hasReceiverDeviceId,
                                  uint32_t receiverDeviceId, const uint8_t* opaque, size_t opaqueLen) {
    signalservice::CallMessage callMessage;
    auto* ice = callMessage.add_iceupdate();
    ice->set_id(callId);
    ice->set_opaque(opaque, opaqueLen);
    if (hasReceiverDeviceId) callMessage.set_destinationdeviceid(receiverDeviceId);
    sendCallMessage(remotePeerId, callMessage, hasReceiverDeviceId, receiverDeviceId);
}

void CallMessageSender::sendHangup(const std::string& remotePeerId, uint64_t callId, int32_t hangupType,
                                     uint32_t hangupDeviceId) {
    signalservice::CallMessage callMessage;
    auto* hangup = callMessage.mutable_hangup();
    hangup->set_id(callId);
    hangup->set_type(static_cast<signalservice::CallMessage_Hangup_Type>(hangupType));
    hangup->set_deviceid(hangupDeviceId);
    sendCallMessage(remotePeerId, callMessage, false, 0);
}

void sendDecryptionErrorReply(AuthSocket& socket, ProtocolStores& stores, const std::string& localServiceId,
                               uint32_t localDeviceId, const std::string& senderServiceId, uint32_t senderDeviceId,
                               const Bytes& originalCiphertext, uint8_t originalType, uint64_t originalTimestamp) {
    try {
        Bytes serializedDem =
            buildDecryptionErrorMessage(originalCiphertext, originalType, originalTimestamp, senderDeviceId);

        signalservice::Content content;
        content.set_decryptionerrormessage(serializedDem.data(), serializedDem.size());
        std::string contentBytes;
        content.SerializeToString(&contentBytes);

        // PlaintextContent's wire format (libsignal's rust/protocol/src/
        // protocol.rs: PLAINTEXT_CONTEXT_IDENTIFIER_BYTE/
        // PADDING_BOUNDARY_BYTE) - deliberately not run through
        // padMessageBody(), this is its own simpler framing, not a normal
        // encrypted message body.
        Bytes plaintextContent{0xC0};
        plaintextContent.insert(plaintextContent.end(), contentBytes.begin(), contentBytes.end());
        plaintextContent.push_back(0x80);

        // The server's mismatched-devices check (Signal-Server's
        // MessageSender/getMismatchedDevices) requires every /v1/messages
        // PUT to address *every* currently-registered device of the
        // destination account, not just the one this reply is really
        // about - addressing only senderDeviceId got a live 409
        // (missing devices) the first time this was tested against a
        // real 3-device account. Unlike an encrypted send, there's no
        // per-device crypto cost to paying that: PlaintextContent isn't
        // Double-Ratchet-encrypted at all, so the exact same bytes go to
        // every device - each one independently decides whether the
        // embedded ratchet key means anything to its own session state.
        // Always re-fetch the full device list (fetchAndEstablishSessions
        // with no device filter) rather than trying the single cached
        // session first - simpler, and this is an already-rare recovery
        // path, not a hot one.
        auto deviceIds = fetchAndEstablishSessions(socket, stores, localServiceId, localDeviceId, senderServiceId);

        // Envelope.Type.PLAINTEXT_CONTENT (proto/SignalService.proto) - not
        // encrypted, see buildDecryptionErrorPlaintextContent()'s doc
        // comment.
        constexpr int kPlaintextContentEnvelopeType = 8;
        json messages = json::array();
        {
            std::lock_guard<std::mutex> lock(stores.mutex());
            for (int deviceId : deviceIds) {
                std::string address = senderServiceId + "." + std::to_string(deviceId);
                uint32_t registrationId = remoteRegistrationIdFromSession(stores.storage(), address);
                messages.push_back({{"type", kPlaintextContentEnvelopeType},
                                     {"destinationDeviceId", deviceId},
                                     {"destinationRegistrationId", registrationId},
                                     {"content", base64Encode(plaintextContent)}});
            }
        }

        auto response = putMessages(socket, senderServiceId, messages, /*online=*/false);
        std::cout << "[daemon] sent DecryptionErrorMessage to " << senderServiceId << " (" << deviceIds.size()
                   << " device(s)) -> " << response.status;
        if (response.status / 100 != 2) {
            std::cout << " (body: " << std::string(response.body.begin(), response.body.end()) << ")";
        }
        std::cout << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[daemon] failed to send DecryptionErrorMessage to " << senderServiceId << "." << senderDeviceId
                   << ": " << e.what() << "\n";
    }
}

} // namespace signal2sip
