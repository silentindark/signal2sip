#include "Crypto.h"

#include <array>

#include "FfiUtil.h"
#include "Padding.h"
#include "../util/Base64.h"

// Same ownership convention as ProtocolStores.cpp: every "Mut pointer"
// value we receive from a signal_* call is ours to destroy once we're done
// with it (see that file's header comment for how this was confirmed
// against libsignal's own Swift bridge).

namespace signal2sip {

namespace {

// Signal's production UnidentifiedDelivery trust roots (app/build.gradle.kts,
// signalapp/Signal-Android) - the first signs current SenderCertificates,
// the second is kept for rotation/compat. Matches flowc-receive.js's
// TRUST_ROOTS exactly.
const std::array<std::string, 2> kTrustRootsBase64 = {
    "BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF",
    "BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6",
};

} // namespace

void establishSession(ProtocolStores& stores, const Address& localAddress, const RemotePreKeyBundle& bundle) {
    SignalMutPointerPublicKey identityKey = publicKeyDeserialize(bundle.identityKey);
    SignalMutPointerPublicKey signedPreKeyPublic = publicKeyDeserialize(bundle.signedPreKeyPublic);
    SignalMutPointerPublicKey preKeyPublic{};
    if (bundle.preKeyPublic) preKeyPublic = publicKeyDeserialize(*bundle.preKeyPublic);

    SignalMutPointerKyberPublicKey kyberPreKeyPublic{};
    checkError(signal_kyber_public_key_deserialize(&kyberPreKeyPublic, borrow(bundle.kyberPreKeyPublic)));

    // Option<u32>::None is represented as u32::MAX at this ABI boundary
    // (confirmed in libsignal's rust/bridge/shared/types/src/ffi/convert.rs
    // SimpleArgTypeInfo<Option<u32>> impl), not 0 - a device with no
    // one-time EC prekey must pass UINT32_MAX here, matching the null
    // `prekey` pointer, or signal_pre_key_bundle_new correctly rejects the
    // "one present, one absent" mismatch.
    uint32_t preKeyIdArg = bundle.preKeyId ? *bundle.preKeyId : UINT32_MAX;
    SignalMutPointerPreKeyBundle preKeyBundle{};
    checkError(signal_pre_key_bundle_new(
        &preKeyBundle, bundle.registrationId, bundle.deviceId, preKeyIdArg,
        SignalConstPointerPublicKey{preKeyPublic.raw}, bundle.signedPreKeyId,
        SignalConstPointerPublicKey{signedPreKeyPublic.raw}, borrow(bundle.signedPreKeySignature),
        SignalConstPointerPublicKey{identityKey.raw}, bundle.kyberPreKeyId,
        SignalConstPointerKyberPublicKey{kyberPreKeyPublic.raw}, borrow(bundle.kyberPreKeySignature)));

    checkError(signal_publickey_destroy(identityKey));
    checkError(signal_publickey_destroy(signedPreKeyPublic));
    if (preKeyPublic.raw) checkError(signal_publickey_destroy(preKeyPublic));
    checkError(signal_kyber_public_key_destroy(kyberPreKeyPublic));

    SignalMutPointerProtocolAddress remote = addressNew(bundle.serviceId, bundle.deviceId);
    SignalMutPointerProtocolAddress local = addressNew(localAddress.serviceId, localAddress.deviceId);

    checkError(signal_process_prekey_bundle(SignalConstPointerPreKeyBundle{preKeyBundle.raw},
                                             SignalConstPointerProtocolAddress{remote.raw},
                                             SignalConstPointerProtocolAddress{local.raw}, stores.sessionStore(),
                                             stores.identityKeyStore(),
                                             /*now=*/0));

    checkError(signal_pre_key_bundle_destroy(preKeyBundle));
    checkError(signal_address_destroy(remote));
    checkError(signal_address_destroy(local));
}

EncryptedMessage encryptForDevice(ProtocolStores& stores, const Address& localAddress, const Address& remoteAddress,
                                  const Bytes& plaintextContent) {
    Bytes padded = padMessageBody(plaintextContent);

    SignalMutPointerProtocolAddress remote = addressNew(remoteAddress.serviceId, remoteAddress.deviceId);
    SignalMutPointerProtocolAddress local = addressNew(localAddress.serviceId, localAddress.deviceId);

    SignalMutPointerCiphertextMessage ciphertext{};
    checkError(signal_encrypt_message(&ciphertext, borrow(padded), SignalConstPointerProtocolAddress{remote.raw},
                                       SignalConstPointerProtocolAddress{local.raw}, stores.sessionStore(),
                                       stores.identityKeyStore(), /*now=*/0));
    checkError(signal_address_destroy(remote));
    checkError(signal_address_destroy(local));

    uint8_t type = 0;
    checkError(signal_ciphertext_message_type(&type, SignalConstPointerCiphertextMessage{ciphertext.raw}));
    SignalOwnedBuffer buffer{};
    checkError(signal_ciphertext_message_serialize(&buffer, SignalConstPointerCiphertextMessage{ciphertext.raw}));
    Bytes bytes = takeOwned(buffer);
    checkError(signal_ciphertext_message_destroy(ciphertext));

    return EncryptedMessage{bytes, type};
}

Bytes decryptCiphertext(ProtocolStores& stores, const Address& localAddress, const Address& remoteAddress,
                        uint8_t messageType, const Bytes& ciphertext) {
    SignalMutPointerProtocolAddress remote = addressNew(remoteAddress.serviceId, remoteAddress.deviceId);
    SignalMutPointerProtocolAddress local = addressNew(localAddress.serviceId, localAddress.deviceId);

    SignalOwnedBuffer buffer{};
    if (messageType == SignalCiphertextMessageTypePreKey) {
        SignalMutPointerPreKeySignalMessage message{};
        checkError(signal_pre_key_signal_message_deserialize(&message, borrow(ciphertext)));
        checkError(signal_decrypt_pre_key_message(&buffer, SignalConstPointerPreKeySignalMessage{message.raw},
                                                   SignalConstPointerProtocolAddress{remote.raw},
                                                   SignalConstPointerProtocolAddress{local.raw}, stores.sessionStore(),
                                                   stores.identityKeyStore(), stores.preKeyStore(),
                                                   stores.signedPreKeyStore(), stores.kyberPreKeyStore()));
        checkError(signal_pre_key_signal_message_destroy(message));
    } else {
        SignalMutPointerSignalMessage message{};
        checkError(signal_message_deserialize(&message, borrow(ciphertext)));
        checkError(signal_decrypt_message(&buffer, SignalConstPointerSignalMessage{message.raw},
                                           SignalConstPointerProtocolAddress{remote.raw},
                                           SignalConstPointerProtocolAddress{local.raw}, stores.sessionStore(),
                                           stores.identityKeyStore()));
        checkError(signal_message_destroy(message));
    }
    checkError(signal_address_destroy(remote));
    checkError(signal_address_destroy(local));

    return stripPaddingMessageBody(takeOwned(buffer));
}

SealedSenderResult decryptSealedSender(ProtocolStores& stores, const Address& localAddress,
                                       const Bytes& sealedSenderCiphertext, uint64_t serverTimestamp) {
    SignalMutPointerUnidentifiedSenderMessageContent usmc{};
    checkError(signal_sealed_session_cipher_decrypt_to_usmc(&usmc, borrow(sealedSenderCiphertext),
                                                             stores.identityKeyStore()));

    SignalMutPointerSenderCertificate cert{};
    checkError(signal_unidentified_sender_message_content_get_sender_cert(
        &cert, SignalConstPointerUnidentifiedSenderMessageContent{usmc.raw}));

    std::vector<SignalMutPointerPublicKey> trustRootHandles;
    std::vector<SignalConstPointerPublicKey> trustRootConstPointers;
    for (const auto& b64 : kTrustRootsBase64) {
        SignalMutPointerPublicKey key = publicKeyDeserialize(base64Decode(b64));
        trustRootHandles.push_back(key);
        trustRootConstPointers.push_back(SignalConstPointerPublicKey{key.raw});
    }

    bool valid = false;
    checkError(signal_sender_certificate_validate(
        &valid, SignalConstPointerSenderCertificate{cert.raw},
        SignalBorrowedSliceOfConstPointerPublicKey{trustRootConstPointers.data(), trustRootConstPointers.size()},
        serverTimestamp));
    for (auto handle : trustRootHandles) checkError(signal_publickey_destroy(handle));
    if (!valid) {
        checkError(signal_sender_certificate_destroy(cert));
        checkError(signal_unidentified_sender_message_content_destroy(usmc));
        throw std::runtime_error("sealed sender: sender certificate failed trust root validation");
    }

    SignalCStringPtr senderUuid = nullptr;
    checkError(signal_sender_certificate_get_sender_uuid(&senderUuid, SignalConstPointerSenderCertificate{cert.raw}));
    std::string senderServiceId(reinterpret_cast<const char*>(senderUuid));
    signal_free_string(senderUuid);

    uint32_t senderDeviceId = 0;
    checkError(
        signal_sender_certificate_get_device_id(&senderDeviceId, SignalConstPointerSenderCertificate{cert.raw}));
    checkError(signal_sender_certificate_destroy(cert));

    uint8_t msgType = 0;
    checkError(signal_unidentified_sender_message_content_get_msg_type(
        &msgType, SignalConstPointerUnidentifiedSenderMessageContent{usmc.raw}));
    SignalOwnedBuffer contentsBuffer{};
    checkError(signal_unidentified_sender_message_content_get_contents(
        &contentsBuffer, SignalConstPointerUnidentifiedSenderMessageContent{usmc.raw}));
    Bytes innerCiphertext = takeOwned(contentsBuffer);
    checkError(signal_unidentified_sender_message_content_destroy(usmc));

    Bytes plaintext =
        decryptCiphertext(stores, localAddress, Address{senderServiceId, senderDeviceId}, msgType, innerCiphertext);
    return SealedSenderResult{senderServiceId, senderDeviceId, plaintext};
}

} // namespace signal2sip
