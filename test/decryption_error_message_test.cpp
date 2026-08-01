// Local, no-network unit test for buildDecryptionErrorMessage() (Crypto.h) -
// the core of this project's new session-recovery feature
// (CallSignaling.cpp's sendDecryptionErrorReply()). Verifies it round-trips
// correctly (deserializes back to the same timestamp/device id) and that
// its ratchet key matches the real sender ratchet key embedded in a
// genuine, freshly-encrypted message - for both message shapes the real
// code path can hit (a fresh session's PreKey message, and an
// already-acknowledged session's Whisper message, since libsignal parses
// each differently to extract the ratchet key).
//
// Fully synthetic two-party setup (Alice sends, Bob's public bundle only,
// no server involved for the PreKey case; Bob gets a real local
// ProtocolStores too so the Whisper case can be reached honestly) - same
// spirit as the RingRTC Milestone E two-process tests, deliberately
// touches chat.signal.org for nothing at all.

#include <cstdint>
#include <cstdio>
#include <iostream>

#include <signal_ffi.h>

#include "../signal/Crypto.h"
#include "../signal/FfiUtil.h"
#include "../signal/PreKeys.h"
#include "../signal/ProtocolStores.h"
#include "../storage/Storage.h"

using namespace signal2sip;

namespace {

struct GeneratedIdentity {
    Bytes privateKey;
    Bytes publicKey;
};

GeneratedIdentity generateIdentity() {
    SignalMutPointerPrivateKey priv{};
    checkError(signal_privatekey_generate(&priv));
    SignalMutPointerPublicKey pub{};
    checkError(signal_privatekey_get_public_key(&pub, SignalConstPointerPrivateKey{priv.raw}));

    SignalOwnedBuffer privBuf{};
    checkError(signal_privatekey_serialize(&privBuf, SignalConstPointerPrivateKey{priv.raw}));
    Bytes privBytes = takeOwned(privBuf);
    checkError(signal_privatekey_destroy(priv));

    Bytes pubBytes = publicKeySerializeAndDestroy(pub);
    return GeneratedIdentity{privBytes, pubBytes};
}

bool expect(bool condition, const char* what) {
    std::cout << (condition ? "PASS" : "FAIL") << ": " << what << "\n";
    return condition;
}

// Independently extracts the real sender ratchet key straight from a
// ciphertext blob, bypassing buildDecryptionErrorMessage() entirely - the
// thing we're checking its output against.
Bytes realSenderRatchetKey(const Bytes& ciphertext, uint8_t type) {
    SignalMutPointerPublicKey ratchetKey{};
    if (type == SignalCiphertextMessageTypePreKey) {
        SignalMutPointerPreKeySignalMessage preKeyMsg{};
        checkError(signal_pre_key_signal_message_deserialize(&preKeyMsg, borrow(ciphertext)));
        SignalMutPointerSignalMessage innerMsg{};
        checkError(signal_pre_key_signal_message_get_signal_message(
            &innerMsg, SignalConstPointerPreKeySignalMessage{preKeyMsg.raw}));
        checkError(signal_message_get_sender_ratchet_key(&ratchetKey, SignalConstPointerSignalMessage{innerMsg.raw}));
        checkError(signal_message_destroy(innerMsg));
        checkError(signal_pre_key_signal_message_destroy(preKeyMsg));
    } else {
        SignalMutPointerSignalMessage msg{};
        checkError(signal_message_deserialize(&msg, borrow(ciphertext)));
        checkError(signal_message_get_sender_ratchet_key(&ratchetKey, SignalConstPointerSignalMessage{msg.raw}));
        checkError(signal_message_destroy(msg));
    }
    return publicKeySerializeAndDestroy(ratchetKey);
}

// Builds a DecryptionErrorMessage for `ciphertext`/`type`, deserializes it
// back, and checks timestamp/device id/ratchet key all match expectations -
// exercising exactly what sendDecryptionErrorReply() depends on.
bool checkRoundTrip(const std::string& label, const Bytes& ciphertext, uint8_t type, uint32_t senderDeviceId) {
    bool ok = true;
    uint64_t originalTimestamp = 1234567890123ULL;

    Bytes dem = buildDecryptionErrorMessage(ciphertext, type, originalTimestamp, senderDeviceId);
    ok &= expect(!dem.empty(), (label + ": buildDecryptionErrorMessage produced non-empty output").c_str());

    SignalMutPointerDecryptionErrorMessage parsed{};
    checkError(signal_decryption_error_message_deserialize(&parsed, borrow(dem)));

    uint64_t parsedTimestamp = 0;
    checkError(signal_decryption_error_message_get_timestamp(
        &parsedTimestamp, SignalConstPointerDecryptionErrorMessage{parsed.raw}));
    ok &= expect(parsedTimestamp == originalTimestamp, (label + ": parsed timestamp matches original").c_str());

    uint32_t parsedDeviceId = 0;
    checkError(
        signal_decryption_error_message_get_device_id(&parsedDeviceId, SignalConstPointerDecryptionErrorMessage{parsed.raw}));
    ok &= expect(parsedDeviceId == senderDeviceId,
                 (label + ": parsed device id matches original sender's device id").c_str());

    SignalMutPointerPublicKey parsedRatchetKey{};
    checkError(signal_decryption_error_message_get_ratchet_key(
        &parsedRatchetKey, SignalConstPointerDecryptionErrorMessage{parsed.raw}));
    ok &= expect(parsedRatchetKey.raw != nullptr, (label + ": parsed ratchet key is present").c_str());

    Bytes parsedRatchetKeyBytes = publicKeySerializeAndDestroy(parsedRatchetKey);
    Bytes expectedRatchetKeyBytes = realSenderRatchetKey(ciphertext, type);
    ok &= expect(parsedRatchetKeyBytes == expectedRatchetKeyBytes,
                 (label + ": parsed ratchet key matches the message's real sender ratchet key").c_str());

    checkError(signal_decryption_error_message_destroy(parsed));
    return ok;
}

} // namespace

int main() {
    bool allOk = true;

    // --- Alice and Bob, both fully local - no chat.signal.org involved. ---
    std::string aliceDbPath = "/tmp/signal2sip_dem_test_alice.db";
    std::string bobDbPath = "/tmp/signal2sip_dem_test_bob.db";
    std::remove(aliceDbPath.c_str());
    std::remove(bobDbPath.c_str());

    Storage aliceStorage(aliceDbPath, "dem-test-key-alice");
    Storage bobStorage(bobDbPath, "dem-test-key-bob");

    GeneratedIdentity aliceIdentity = generateIdentity();
    GeneratedIdentity bobIdentity = generateIdentity();

    aliceStorage.saveAccount(AccountRecord{"+15550100", "alice-aci", "alice-pni", "alice-password", 1, 1, 1});
    aliceStorage.saveIdentityKeypair("aci", IdentityKeypairRecord{aliceIdentity.privateKey, aliceIdentity.publicKey});
    bobStorage.saveAccount(AccountRecord{"+15550199", "bob-aci", "bob-pni", "bob-password", 7, 1, 1});
    bobStorage.saveIdentityKeypair("aci", IdentityKeypairRecord{bobIdentity.privateKey, bobIdentity.publicKey});

    ProtocolStores aliceStores(aliceStorage, "aci");
    ProtocolStores bobStores(bobStorage, "aci");
    Address aliceAddress{"alice-aci", 1};
    Address bobAddress{"bob-aci", 7};

    GeneratedSignedPreKey bobSignedPreKey = generateSignedPreKey(bobIdentity.privateKey, 1);
    GeneratedKyberPreKey bobKyberPreKey = generateKyberPreKey(bobIdentity.privateKey, 1);
    bobStorage.saveSignedPrekey("aci", bobSignedPreKey.stored);
    bobStorage.saveKyberPrekey("aci", bobKyberPreKey.stored);

    RemotePreKeyBundle bobBundle;
    bobBundle.serviceId = bobAddress.serviceId;
    bobBundle.deviceId = bobAddress.deviceId;
    bobBundle.registrationId = 42;
    bobBundle.signedPreKeyId = bobSignedPreKey.wire.keyId;
    bobBundle.signedPreKeyPublic = bobSignedPreKey.wire.publicKey;
    bobBundle.signedPreKeySignature = bobSignedPreKey.wire.signature;
    bobBundle.identityKey = bobIdentity.publicKey;
    bobBundle.kyberPreKeyId = bobKyberPreKey.wire.keyId;
    bobBundle.kyberPreKeyPublic = bobKyberPreKey.wire.publicKey;
    bobBundle.kyberPreKeySignature = bobKyberPreKey.wire.signature;
    // No one-time EC prekey (bundle.preKeyId left unset) - matches a
    // depleted-one-time-prekeys real bundle, still perfectly valid.

    establishSession(aliceStores, aliceAddress, bobBundle);
    allOk &= expect(true, "established Alice -> Bob session locally (no network)");

    // --- Message #1: fresh session -> PreKey message. ---
    std::string text1 = "hello bob, this is alice";
    Bytes plaintext1(text1.begin(), text1.end());
    EncryptedMessage msg1 = encryptForDevice(aliceStores, aliceAddress, bobAddress, plaintext1);
    allOk &= expect(msg1.type == SignalCiphertextMessageTypePreKey, "message #1 is a PreKey message (fresh session)");
    allOk &= checkRoundTrip("PreKey message", msg1.ciphertext, msg1.type, aliceAddress.deviceId);

    // --- Complete the handshake for real: Bob decrypts #1 (establishing
    // his own receiving session honestly, not synthesized), replies, and
    // Alice decrypts the reply - after which her *next* send switches to
    // Whisper, matching this project's own earlier finding that a session
    // stays in "unacknowledged PreKey" mode until a reply is processed. ---
    Bytes decrypted1 = decryptCiphertext(bobStores, bobAddress, aliceAddress, msg1.type, msg1.ciphertext);
    allOk &= expect(std::string(decrypted1.begin(), decrypted1.end()) == text1,
                     "Bob genuinely decrypted message #1");

    std::string replyText = "hi alice, bob here";
    Bytes replyPlaintext(replyText.begin(), replyText.end());
    EncryptedMessage reply = encryptForDevice(bobStores, bobAddress, aliceAddress, replyPlaintext);
    Bytes decryptedReply = decryptCiphertext(aliceStores, aliceAddress, bobAddress, reply.type, reply.ciphertext);
    allOk &= expect(std::string(decryptedReply.begin(), decryptedReply.end()) == replyText,
                     "Alice genuinely decrypted Bob's reply (handshake acknowledged)");

    // --- Message #2: acknowledged session -> Whisper message. ---
    std::string text2 = "second message, should be Whisper now";
    Bytes plaintext2(text2.begin(), text2.end());
    EncryptedMessage msg2 = encryptForDevice(aliceStores, aliceAddress, bobAddress, plaintext2);
    allOk &= expect(msg2.type == SignalCiphertextMessageTypeWhisper,
                     "message #2 is a Whisper message (acknowledged session)");
    allOk &= checkRoundTrip("Whisper message", msg2.ciphertext, msg2.type, aliceAddress.deviceId);

    std::cout << (allOk ? "PASS" : "FAIL") << ": DecryptionErrorMessage round-trips for both message types\n";
    return allOk ? 0 : 1;
}
