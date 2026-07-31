#include "ProtocolStores.h"

#include <cstring>
#include <iostream>
#include <string>

#include "FfiUtil.h"

// Ownership convention used throughout this file, confirmed against
// libsignal's own Swift bridge (swift/Sources/LibSignalClient/
// DataStoreUtils.swift + NativeHandleOwner.swift, which wraps every
// "Mut pointer" callback argument in a class whose deinit calls the
// matching signal_*_destroy - i.e. callbacks receive ownership of every
// address/record/key handle passed in and must destroy it before
// returning, and *_new/*_deserialize calls used to build an `out` value
// hand a fresh owned handle to libsignal, which takes ownership of it).
//
// Every callback below therefore: destroys every incoming Mut-pointer
// argument exactly once (even on the no-op paths), and never touches a
// handle after handing it to libsignal via an `out` parameter.

namespace signal2sip {

namespace {

template <typename F>
int32_t guardCallback(F&& f) {
    try {
        f();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[daemon][DIAG] ProtocolStores callback threw: " << e.what() << "\n";
        return -1;
    } catch (...) {
        std::cerr << "[daemon][DIAG] ProtocolStores callback threw non-std::exception\n";
        return -1;
    }
}

// Bare serviceId part of an address key (before the last '.'), used to key
// remote_identity (trust-on-first-use is per-identity, not per-device).
std::string serviceIdFromAddressKey(const std::string& addressKey) {
    auto dot = addressKey.rfind('.');
    return dot == std::string::npos ? addressKey : addressKey.substr(0, dot);
}

} // namespace

ProtocolStores::ProtocolStores(Storage& storage, std::string identity)
    : storage_(storage), identity_(std::move(identity)) {
    sessionStoreStruct_.ctx = this;
    sessionStoreStruct_.destroy = [](void*) {};
    sessionStoreStruct_.load_session = [](void* ctx, SignalMutPointerSessionRecord* out,
                                           SignalMutPointerProtocolAddress address) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            std::string key = addressKeyAndDestroy(address);
            auto record = self->storage_.loadSession(key);
            if (!record) {
                *out = SignalMutPointerSessionRecord{};
                return;
            }
            checkError(signal_session_record_deserialize(out, borrow(*record)));
        });
    };
    sessionStoreStruct_.store_session = [](void* ctx, SignalMutPointerProtocolAddress address,
                                            SignalMutPointerSessionRecord record) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            std::string key = addressKeyAndDestroy(address);
            SignalOwnedBuffer buffer{};
            checkError(signal_session_record_serialize(&buffer, SignalConstPointerSessionRecord{record.raw}));
            Bytes bytes = takeOwned(buffer);
            checkError(signal_session_record_destroy(record));
            self->storage_.saveSession(key, bytes);
        });
    };

    identityKeyStoreStruct_.ctx = this;
    identityKeyStoreStruct_.destroy = [](void*) {};
    identityKeyStoreStruct_.get_local_identity_key_pair =
        [](void* ctx, SignalPairOfMutPointerPrivateKeyMutPointerPublicKey* out) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            auto keypair = self->storage_.loadIdentityKeypair(self->identity_);
            if (!keypair) throw std::runtime_error("no identity keypair stored for " + self->identity_);
            out->first = privateKeyDeserialize(keypair->private_key);
            out->second = publicKeyDeserialize(keypair->public_key);
        });
    };
    identityKeyStoreStruct_.get_local_registration_id = [](void* ctx, uint32_t* out) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            AccountRecord account = self->storage_.loadAccount();
            *out = static_cast<uint32_t>(
                self->identity_ == "pni" ? account.pni_registration_id : account.registration_id);
        });
    };
    identityKeyStoreStruct_.get_identity_key = [](void* ctx, SignalMutPointerPublicKey* out,
                                                   SignalMutPointerProtocolAddress address) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            std::string key = serviceIdFromAddressKey(addressKeyAndDestroy(address));
            auto stored = self->storage_.loadRemoteIdentity(key);
            *out = stored ? publicKeyDeserialize(*stored) : SignalMutPointerPublicKey{};
        });
    };
    identityKeyStoreStruct_.save_identity_key = [](void* ctx, uint8_t* result,
                                                    SignalMutPointerProtocolAddress address,
                                                    SignalMutPointerPublicKey publicKey) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            std::string key = serviceIdFromAddressKey(addressKeyAndDestroy(address));
            Bytes newKeyBytes = publicKeySerializeAndDestroy(publicKey);
            auto existing = self->storage_.loadRemoteIdentity(key);
            self->storage_.saveRemoteIdentity(key, newKeyBytes);
            // SignalIdentityChangeNewOrUnchanged=0 / SignalIdentityChangeReplacedExisting=1,
            // matching layer1/protocolStores.js's AccountIdentityStore.saveIdentity() semantics.
            *result = (existing && *existing != newKeyBytes) ? 1 : 0;
        });
    };
    identityKeyStoreStruct_.is_trusted_identity = [](void* ctx, bool* result,
                                                      SignalMutPointerProtocolAddress address,
                                                      SignalMutPointerPublicKey publicKey,
                                                      uint32_t /*direction*/) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            std::string key = serviceIdFromAddressKey(addressKeyAndDestroy(address));
            Bytes candidate = publicKeySerializeAndDestroy(publicKey);
            auto existing = self->storage_.loadRemoteIdentity(key);
            // Trust-on-first-use, matching AccountIdentityStore.isTrustedIdentity: nothing
            // stored yet -> trust and let save_identity_key record it.
            *result = !existing || *existing == candidate;
        });
    };

    // We never upload one-time EC prekeys (matches AccountPreKeyStore in
    // the Node prototype), so the server only ever hands out our
    // signed+last-resort-kyber keys - load_pre_key should never actually be
    // called for a real incoming message.
    preKeyStoreStruct_.ctx = this;
    preKeyStoreStruct_.destroy = [](void*) {};
    preKeyStoreStruct_.load_pre_key = [](void*, SignalMutPointerPreKeyRecord*, uint32_t) -> int32_t {
        return -1;
    };
    preKeyStoreStruct_.store_pre_key = [](void*, uint32_t, SignalMutPointerPreKeyRecord record) -> int32_t {
        return guardCallback([&] { checkError(signal_pre_key_record_destroy(record)); });
    };
    preKeyStoreStruct_.remove_pre_key = [](void*, uint32_t) -> int32_t { return 0; };

    signedPreKeyStoreStruct_.ctx = this;
    signedPreKeyStoreStruct_.destroy = [](void*) {};
    signedPreKeyStoreStruct_.load_signed_pre_key = [](void* ctx, SignalMutPointerSignedPreKeyRecord* out,
                                                       uint32_t id) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            auto stored = self->storage_.loadSignedPrekey(self->identity_);
            if (!stored || stored->key_id != static_cast<int64_t>(id)) {
                throw std::runtime_error("no signed prekey " + std::to_string(id) + " on file");
            }
            checkError(signal_signed_pre_key_record_deserialize(out, borrow(stored->record)));
        });
    };
    signedPreKeyStoreStruct_.store_signed_pre_key = [](void* ctx, uint32_t id,
                                                        SignalMutPointerSignedPreKeyRecord record) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            SignalOwnedBuffer buffer{};
            checkError(
                signal_signed_pre_key_record_serialize(&buffer, SignalConstPointerSignedPreKeyRecord{record.raw}));
            Bytes bytes = takeOwned(buffer);
            checkError(signal_signed_pre_key_record_destroy(record));
            self->storage_.saveSignedPrekey(self->identity_, SignedPrekeyRecord{static_cast<int64_t>(id), bytes});
        });
    };

    kyberPreKeyStoreStruct_.ctx = this;
    kyberPreKeyStoreStruct_.destroy = [](void*) {};
    kyberPreKeyStoreStruct_.load_kyber_pre_key = [](void* ctx, SignalMutPointerKyberPreKeyRecord* out,
                                                     uint32_t id) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            auto stored = self->storage_.loadKyberPrekey(self->identity_);
            if (!stored || stored->key_id != static_cast<int64_t>(id)) {
                throw std::runtime_error("no kyber prekey " + std::to_string(id) + " on file");
            }
            checkError(signal_kyber_pre_key_record_deserialize(out, borrow(stored->record)));
        });
    };
    kyberPreKeyStoreStruct_.store_kyber_pre_key = [](void* ctx, uint32_t id,
                                                      SignalMutPointerKyberPreKeyRecord record) -> int32_t {
        auto* self = static_cast<ProtocolStores*>(ctx);
        return guardCallback([&] {
            SignalOwnedBuffer buffer{};
            checkError(
                signal_kyber_pre_key_record_serialize(&buffer, SignalConstPointerKyberPreKeyRecord{record.raw}));
            Bytes bytes = takeOwned(buffer);
            checkError(signal_kyber_pre_key_record_destroy(record));
            self->storage_.saveKyberPrekey(self->identity_, KyberPrekeyRecord{static_cast<int64_t>(id), bytes});
        });
    };
    // Last-resort key is reusable by design (matches AccountKyberPreKeyStore) -
    // still must destroy the owned baseKey handle we're passed.
    kyberPreKeyStoreStruct_.mark_kyber_pre_key_used = [](void*, uint32_t, uint32_t,
                                                          SignalMutPointerPublicKey baseKey) -> int32_t {
        return guardCallback([&] { checkError(signal_publickey_destroy(baseKey)); });
    };
}

SignalConstPointerFfiSessionStoreStruct ProtocolStores::sessionStore() const {
    return SignalConstPointerFfiSessionStoreStruct{&sessionStoreStruct_};
}

SignalConstPointerFfiIdentityKeyStoreStruct ProtocolStores::identityKeyStore() const {
    return SignalConstPointerFfiIdentityKeyStoreStruct{&identityKeyStoreStruct_};
}

SignalConstPointerFfiPreKeyStoreStruct ProtocolStores::preKeyStore() const {
    return SignalConstPointerFfiPreKeyStoreStruct{&preKeyStoreStruct_};
}

SignalConstPointerFfiSignedPreKeyStoreStruct ProtocolStores::signedPreKeyStore() const {
    return SignalConstPointerFfiSignedPreKeyStoreStruct{&signedPreKeyStoreStruct_};
}

SignalConstPointerFfiKyberPreKeyStoreStruct ProtocolStores::kyberPreKeyStore() const {
    return SignalConstPointerFfiKyberPreKeyStoreStruct{&kyberPreKeyStoreStruct_};
}

} // namespace signal2sip
