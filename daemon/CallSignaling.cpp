#include "CallSignaling.h"

#include <chrono>
#include <iostream>

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
// device it reports. Returns the resulting device ids.
std::vector<int> fetchAndEstablishSessions(AuthSocket& socket, ProtocolStores& stores,
                                            const std::string& localServiceId, uint32_t localDeviceId,
                                            const std::string& remoteServiceId) {
    Address localAddress{localServiceId, localDeviceId};
    auto response = socket.request("GET", "/v2/keys/" + remoteServiceId + "/*");
    if (response.status != 200) {
        throw std::runtime_error("GET /v2/keys/" + remoteServiceId + "/* -> " + std::to_string(response.status));
    }
    json body = json::parse(std::string(response.body.begin(), response.body.end()));
    Bytes identityKey = base64Decode(body.at("identityKey").get<std::string>());

    std::vector<int> deviceIds;
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

        establishSession(stores, localAddress, bundle);
        deviceIds.push_back(static_cast<int>(bundle.deviceId));
    }
    return deviceIds;
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

        Bytes senderIdentityKey(32, 0);
        if (auto stored = stores.storage().loadRemoteIdentity(senderServiceId)) {
            senderIdentityKey = rawPublicKeyBytes(*stored);
        }
        Bytes receiverIdentityKey(32, 0);
        if (auto keypair = stores.storage().loadIdentityKeypair(stores.identity())) {
            receiverIdentityKey = rawPublicKeyBytes(keypair->public_key);
        }

        const std::string& opaque = offer.opaque();
        signal2sip_call_received_offer(handle, senderServiceId.c_str(), offer.id(), senderDeviceId, localDeviceId,
                                        reinterpret_cast<const uint8_t*>(opaque.data()), opaque.size(),
                                        senderIdentityKey.data(), receiverIdentityKey.data());
    }
    if (callMessage.has_answer()) {
        const auto& answer = callMessage.answer();
        const std::string& opaque = answer.opaque();
        signal2sip_call_received_answer(handle, senderServiceId.c_str(), answer.id(), senderDeviceId,
                                         reinterpret_cast<const uint8_t*>(opaque.data()), opaque.size());
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
    if (hasReceiverDeviceId) {
        deviceIds.push_back(static_cast<int>(receiverDeviceId));
        std::string address = remotePeerId + "." + std::to_string(receiverDeviceId);
        if (!stores_.storage().loadSession(address)) {
            fetchAndEstablishSessions(socket_, stores_, localServiceId_, localDeviceId_, remotePeerId);
        }
    } else {
        deviceIds = stores_.storage().knownDeviceIdsFor(remotePeerId);
        if (deviceIds.empty()) {
            deviceIds = fetchAndEstablishSessions(socket_, stores_, localServiceId_, localDeviceId_, remotePeerId);
        }
    }
    if (deviceIds.empty()) return deviceIds;

    signalservice::Content content;
    *content.mutable_callmessage() = callMessage;
    std::string contentBytes;
    content.SerializeToString(&contentBytes);
    Bytes plaintext(contentBytes.begin(), contentBytes.end());

    // Serialize against every other encrypt/decrypt through this
    // account's session store (concurrent sends, or a send racing the
    // websocket thread's decrypt of an incoming envelope, can otherwise
    // interleave Double Ratchet chain updates - see ProtocolStores::mutex()).
    std::lock_guard<std::mutex> lock(stores_.mutex());

    Address localAddress{localServiceId_, localDeviceId_};
    json messages = json::array();
    for (int deviceId : deviceIds) {
        EncryptedMessage encrypted =
            encryptForDevice(stores_, localAddress, Address{remotePeerId, static_cast<uint32_t>(deviceId)}, plaintext);
        int envelopeType = encrypted.type == SignalCiphertextMessageTypePreKey ? 3 : 1;
        std::string address = remotePeerId + "." + std::to_string(deviceId);
        messages.push_back({{"type", envelopeType},
                             {"destinationDeviceId", deviceId},
                             {"destinationRegistrationId", remoteRegistrationIdFromSession(stores_.storage(), address)},
                             {"content", base64Encode(encrypted.ciphertext)}});
    }

    json requestBody = {
        {"destination", remotePeerId}, {"timestamp", nowMs()}, {"messages", messages},
        {"online", true},              {"urgent", true},
    };
    std::string bodyStr = requestBody.dump();
    Bytes bodyBytes(bodyStr.begin(), bodyStr.end());
    auto response = socket_.request("PUT", "/v1/messages/" + remotePeerId + "?story=false", &bodyBytes);
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

} // namespace signal2sip
