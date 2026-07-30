#include "PreKeys.h"

#include <chrono>

#include "FfiUtil.h"

namespace signal2sip {

namespace {

uint64_t nowMillis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

GeneratedSignedPreKey generateSignedPreKey(const Bytes& identityPrivateKey, int64_t keyId) {
    SignalMutPointerPrivateKey keyPair{};
    checkError(signal_privatekey_generate(&keyPair));
    SignalMutPointerPublicKey publicKey{};
    checkError(signal_privatekey_get_public_key(&publicKey, SignalConstPointerPrivateKey{keyPair.raw}));

    SignalOwnedBuffer publicKeyBuffer{};
    checkError(signal_publickey_serialize(&publicKeyBuffer, SignalConstPointerPublicKey{publicKey.raw}));
    Bytes publicKeyBytes = takeOwned(publicKeyBuffer);

    SignalMutPointerPrivateKey identityKey = privateKeyDeserialize(identityPrivateKey);
    SignalOwnedBuffer signatureBuffer{};
    checkError(signal_privatekey_sign(&signatureBuffer, SignalConstPointerPrivateKey{identityKey.raw},
                                       borrow(publicKeyBytes)));
    Bytes signatureBytes = takeOwned(signatureBuffer);
    checkError(signal_privatekey_destroy(identityKey));

    uint64_t timestamp = nowMillis();
    SignalMutPointerSignedPreKeyRecord record{};
    checkError(signal_signed_pre_key_record_new(&record, static_cast<uint32_t>(keyId), timestamp,
                                                 SignalConstPointerPublicKey{publicKey.raw},
                                                 SignalConstPointerPrivateKey{keyPair.raw}, borrow(signatureBytes)));

    SignalOwnedBuffer recordBuffer{};
    checkError(signal_signed_pre_key_record_serialize(&recordBuffer, SignalConstPointerSignedPreKeyRecord{record.raw}));
    Bytes recordBytes = takeOwned(recordBuffer);

    checkError(signal_signed_pre_key_record_destroy(record));
    checkError(signal_publickey_destroy(publicKey));
    checkError(signal_privatekey_destroy(keyPair));

    GeneratedSignedPreKey result;
    result.wire = WirePreKey{keyId, publicKeyBytes, signatureBytes};
    result.stored = SignedPrekeyRecord{keyId, recordBytes};
    return result;
}

GeneratedKyberPreKey generateKyberPreKey(const Bytes& identityPrivateKey, int64_t keyId) {
    SignalMutPointerKyberKeyPair keyPair{};
    checkError(signal_kyber_key_pair_generate(&keyPair));
    SignalMutPointerKyberPublicKey publicKey{};
    checkError(signal_kyber_key_pair_get_public_key(&publicKey, SignalConstPointerKyberKeyPair{keyPair.raw}));

    SignalOwnedBuffer publicKeyBuffer{};
    checkError(signal_kyber_public_key_serialize(&publicKeyBuffer, SignalConstPointerKyberPublicKey{publicKey.raw}));
    Bytes publicKeyBytes = takeOwned(publicKeyBuffer);

    SignalMutPointerPrivateKey identityKey = privateKeyDeserialize(identityPrivateKey);
    SignalOwnedBuffer signatureBuffer{};
    checkError(signal_privatekey_sign(&signatureBuffer, SignalConstPointerPrivateKey{identityKey.raw},
                                       borrow(publicKeyBytes)));
    Bytes signatureBytes = takeOwned(signatureBuffer);
    checkError(signal_privatekey_destroy(identityKey));

    uint64_t timestamp = nowMillis();
    SignalMutPointerKyberPreKeyRecord record{};
    checkError(signal_kyber_pre_key_record_new(&record, static_cast<uint32_t>(keyId), timestamp,
                                                SignalConstPointerKyberKeyPair{keyPair.raw}, borrow(signatureBytes)));

    SignalOwnedBuffer recordBuffer{};
    checkError(signal_kyber_pre_key_record_serialize(&recordBuffer, SignalConstPointerKyberPreKeyRecord{record.raw}));
    Bytes recordBytes = takeOwned(recordBuffer);

    checkError(signal_kyber_pre_key_record_destroy(record));
    checkError(signal_kyber_public_key_destroy(publicKey));
    checkError(signal_kyber_key_pair_destroy(keyPair));

    GeneratedKyberPreKey result;
    result.wire = WirePreKey{keyId, publicKeyBytes, signatureBytes};
    result.stored = KyberPrekeyRecord{keyId, recordBytes};
    return result;
}

} // namespace signal2sip
