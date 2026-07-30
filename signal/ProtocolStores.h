#pragma once

#include <signal_ffi.h>

#include <string>

#include "../storage/Storage.h"

namespace signal2sip {

// Owns the libsignal FFI callback vtables (SessionStore, IdentityKeyStore,
// PreKeyStore, SignedPreKeyStore, KyberPreKeyStore) for one (Storage,
// identity) pair, identity being "aci" or "pni" (see PROTOCOL.md - ACI and
// PNI are different identities with their own signed/kyber prekeys).
// Sessions and remote identity trust are shared across aci/pni for the same
// account, matching layer1/protocolStores.js's buildStores(): one
// FileSessionStore per account, reused for both identities.
//
// One instance must outlive every signal_* call it's passed to (the
// SignalConstPointerFfi*StoreStruct pointers returned below point into this
// object's own storage).
class ProtocolStores {
public:
    ProtocolStores(Storage& storage, std::string identity);

    SignalConstPointerFfiSessionStoreStruct sessionStore() const;
    SignalConstPointerFfiIdentityKeyStoreStruct identityKeyStore() const;
    SignalConstPointerFfiPreKeyStoreStruct preKeyStore() const;
    SignalConstPointerFfiSignedPreKeyStoreStruct signedPreKeyStore() const;
    SignalConstPointerFfiKyberPreKeyStoreStruct kyberPreKeyStore() const;

    Storage& storage() const { return storage_; }
    const std::string& identity() const { return identity_; }

private:
    Storage& storage_;
    std::string identity_;
    SignalFfiSessionStoreStruct sessionStoreStruct_{};
    SignalFfiIdentityKeyStoreStruct identityKeyStoreStruct_{};
    SignalFfiPreKeyStoreStruct preKeyStoreStruct_{};
    SignalFfiSignedPreKeyStoreStruct signedPreKeyStoreStruct_{};
    SignalFfiKyberPreKeyStoreStruct kyberPreKeyStoreStruct_{};
};

} // namespace signal2sip
