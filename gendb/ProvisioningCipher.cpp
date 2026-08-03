#include "ProvisioningCipher.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <stdexcept>

#include "../signal/FfiUtil.h"

namespace signal2sip {

namespace {

constexpr size_t kIvLength = 16;
constexpr size_t kMacLength = 32;
const char kInfo[] = "TextSecure Provisioning Message";

Bytes hmacSha256(const Bytes& key, const Bytes& data) {
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int outLen = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), out, &outLen)) {
        throw std::runtime_error("HMAC-SHA256 failed");
    }
    return Bytes(out, out + outLen);
}

Bytes aes256CbcDecrypt(const Bytes& key, const Bytes& iv, const Bytes& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    Bytes plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0;
    int plaintextLen = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) == 1;
    ok = ok &&
         EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), static_cast<int>(ciphertext.size())) == 1;
    if (ok) plaintextLen = len;
    ok = ok && EVP_DecryptFinal_ex(ctx, plaintext.data() + plaintextLen, &len) == 1;
    if (ok) plaintextLen += len;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) throw std::runtime_error("Provisioning cipher: AES-256-CBC decrypt failed (bad key/iv/padding)");
    plaintext.resize(plaintextLen);
    return plaintext;
}

} // namespace

Bytes decryptProvisionEnvelope(const Bytes& ourPrivateKey, const Bytes& envelopePublicKey, const Bytes& envelopeBody) {
    if (envelopeBody.size() <= 1 + kIvLength + kMacLength) {
        throw std::runtime_error("Provisioning envelope body too short");
    }

    uint8_t version = envelopeBody[0];
    if (version != 1) {
        throw std::runtime_error("Provisioning cipher version mismatch: expected 1, got " +
                                  std::to_string(static_cast<int>(version)));
    }

    Bytes iv(envelopeBody.begin() + 1, envelopeBody.begin() + 1 + kIvLength);
    Bytes theirMac(envelopeBody.end() - kMacLength, envelopeBody.end());
    Bytes macInput(envelopeBody.begin(), envelopeBody.end() - kMacLength);
    Bytes ciphertext(envelopeBody.begin() + 1 + kIvLength, envelopeBody.end() - kMacLength);

    SignalMutPointerPrivateKey ourKey = privateKeyDeserialize(ourPrivateKey);
    SignalMutPointerPublicKey theirKey = publicKeyDeserialize(envelopePublicKey);
    SignalOwnedBuffer sharedSecretBuffer{};
    checkError(signal_privatekey_agree(&sharedSecretBuffer, SignalConstPointerPrivateKey{ourKey.raw},
                                        SignalConstPointerPublicKey{theirKey.raw}));
    Bytes sharedSecret = takeOwned(sharedSecretBuffer);
    checkError(signal_publickey_destroy(theirKey));
    checkError(signal_privatekey_destroy(ourKey));

    Bytes derived(64);
    Bytes info(kInfo, kInfo + sizeof(kInfo) - 1);
    Bytes salt; // empty - matches layer1/provisioningCipher.js's Buffer.alloc(0)
    checkError(signal_hkdf_derive(SignalBorrowedMutableBuffer{derived.data(), derived.size()}, borrow(sharedSecret),
                                   borrow(info), borrow(salt)));
    Bytes cipherKey(derived.begin(), derived.begin() + 32);
    Bytes macKey(derived.begin() + 32, derived.end());

    Bytes ourMac = hmacSha256(macKey, macInput);
    if (ourMac.size() != theirMac.size() || CRYPTO_memcmp(ourMac.data(), theirMac.data(), ourMac.size()) != 0) {
        throw std::runtime_error("Provisioning cipher MAC mismatch");
    }

    return aes256CbcDecrypt(cipherKey, iv, ciphertext);
}

} // namespace signal2sip
