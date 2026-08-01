#pragma once

#include <signal_ffi.h>

#include <mutex>
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

    // Double Ratchet session state (send and receive chains alike) is a
    // strictly-ordered, mutate-in-place resource - two libsignal calls
    // touching the same session concurrently (e.g. the daemon's RingRTC
    // callback thread encrypting an outgoing CallMessage while the
    // websocket thread decrypts an incoming one, or several outgoing
    // sends racing each other) can interleave read-modify-write session
    // updates and corrupt the chain, producing an "invalid Whisper
    // message: decryption failed" on the other end for an otherwise
    // perfectly legitimate message. Found live in Milestone G: a real
    // two-daemon call reliably lost one CallMessage (usually an ICE
    // candidate, sent in a rapid burst) this way. Every call site that
    // encrypts or decrypts through this instance must hold this lock for
    // the duration of that libsignal call.
    //
    // Never hold it across blocking network I/O. AuthSocket runs a single
    // service thread that both delivers every response to
    // AuthSocket::request() and invokes every server-pushed message's
    // callback (onPush) - if a thread holds this mutex while blocked
    // inside request() waiting for its own response, and a new push
    // arrives in the meantime, the service thread blocks trying to
    // acquire this same mutex to handle it, and can then never return to
    // servicing the socket to deliver the response the first thread is
    // waiting on. Found live: this exact self-deadlock, reintroducing the
    // one main.cpp's onPush() dispatch was written to avoid, surfaced as
    // "PUT /v1/messages ... timed out waiting for a response" exactly at
    // AuthSocket::request()'s hard-coded timeout. Lock narrowly around
    // just the libsignal/Storage calls; do the network call unlocked.
    std::mutex& mutex() { return mutex_; }

private:
    Storage& storage_;
    std::string identity_;
    std::mutex mutex_;
    SignalFfiSessionStoreStruct sessionStoreStruct_{};
    SignalFfiIdentityKeyStoreStruct identityKeyStoreStruct_{};
    SignalFfiPreKeyStoreStruct preKeyStoreStruct_{};
    SignalFfiSignedPreKeyStoreStruct signedPreKeyStoreStruct_{};
    SignalFfiKyberPreKeyStoreStruct kyberPreKeyStoreStruct_{};
};

} // namespace signal2sip
