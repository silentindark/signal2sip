#include "DeviceNameCipher.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdexcept>

#include "DeviceName.pb.h"
#include "../signal/FfiUtil.h"
#include "../util/Base64.h"

namespace signal2sip {

namespace {

Bytes hmacSha256(const Bytes& key, const Bytes& data) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out, &outLen)) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }
    return Bytes(out, out + outLen);
}

Bytes bytesFromLiteral(const char* s) {
    return Bytes(s, s + std::char_traits<char>::length(s));
}

Bytes aes256CtrEncrypt(const Bytes& key, const Bytes& iv, const Bytes& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    Bytes ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int ciphertextLen = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv.data()) == 1;
    ok = ok &&
         EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) == 1;
    if (ok) ciphertextLen = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, ciphertext.data() + ciphertextLen, &len) == 1;
    if (ok) ciphertextLen += len;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("DeviceName cipher: AES-256-CTR encrypt failed");
    ciphertext.resize(ciphertextLen);
    return ciphertext;
}

} // namespace

std::string encryptDeviceName(const std::string& plaintextDeviceName, const Bytes& aciIdentityPrivateKey) {
    Bytes plaintext(plaintextDeviceName.begin(), plaintextDeviceName.end());

    KeyPair ephemeral = generateKeyPair();

    // masterSecret = X25519(aciIdentityPrivateKey, ephemeral.publicKey) -
    // deliberately combining OUR OWN identity private key with an ephemeral
    // public key we just generated (not a normal two-party ECDH). Whoever
    // later decrypts this (the same account, via the same ACI identity
    // private key, using ephemeral.publicKey stashed in the proto)
    // recomputes the exact same masterSecret - see DeviceNameUtil.java's
    // own decrypt() doing the identical calculateAgreement() call.
    SignalMutPointerPrivateKey ourKey = privateKeyDeserialize(aciIdentityPrivateKey);
    SignalMutPointerPublicKey ephemeralPub = publicKeyDeserialize(ephemeral.publicKey);
    SignalOwnedBuffer sharedSecretBuffer{};
    checkError(signal_privatekey_agree(&sharedSecretBuffer, SignalConstPointerPrivateKey{ourKey.raw},
                                        SignalConstPointerPublicKey{ephemeralPub.raw}));
    Bytes masterSecret = takeOwned(sharedSecretBuffer);
    checkError(signal_publickey_destroy(ephemeralPub));
    checkError(signal_privatekey_destroy(ourKey));

    Bytes key1 = hmacSha256(masterSecret, bytesFromLiteral("auth"));
    Bytes syntheticIvFull = hmacSha256(key1, plaintext);
    Bytes syntheticIv(syntheticIvFull.begin(), syntheticIvFull.begin() + 16);

    Bytes key2 = hmacSha256(masterSecret, bytesFromLiteral("cipher"));
    Bytes cipherKey = hmacSha256(key2, syntheticIv);

    Bytes zeroIv(16, 0);
    Bytes ciphertext = aes256CtrEncrypt(cipherKey, zeroIv, plaintext);

    signalservice::DeviceName deviceName;
    deviceName.set_ephemeralpublic(ephemeral.publicKey.data(), ephemeral.publicKey.size());
    deviceName.set_syntheticiv(syntheticIv.data(), syntheticIv.size());
    deviceName.set_ciphertext(ciphertext.data(), ciphertext.size());

    std::string serialized;
    deviceName.SerializeToString(&serialized);
    return base64Encode(Bytes(serialized.begin(), serialized.end()));
}

} // namespace signal2sip
