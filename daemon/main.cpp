// signal2sip-daemon: one process serving N Signal accounts at once (each
// optionally with its own SIP trunk), driven entirely by real
// incoming/outgoing Signal calls - no IPC, no Node. Real Signal Protocol
// send/receive, RingRTC calling, and the PJSIP ring-buffer bridge, all
// per-account.
//
// Was one process per account (mirroring tg2sip-webrtc's own model) -
// deliberately reversed to single-process-multi-account; see the
// project's own memory for that decision and Config.h's doc comment for
// the resulting config file shape.
//
// Two roles a given account can take, inferred from its own config
// section (not an explicit mode flag):
//   - Incoming Signal call + [sip.<name>] bridge_destination configured:
//     answers automatically and bridges the call's audio to a real SIP
//     call via RingRtcSipBridge (native/voip/), same pattern
//     pjsip_ringrtc_echo_test.cpp's peerB proved live against DPDZK's *43.
//   - [other.<name>] outgoing_call_target configured: places an outgoing
//     Signal call and pushes/pulls raw audio directly (no SIP leg) - a
//     test probe, measuring RMS to confirm the round trip through the
//     other account's SIP bridge actually carried real audio. Mirrors
//     pjsip_ringrtc_echo_test.cpp's peerA.
//
// Concurrent calls across DIFFERENT accounts are fully supported (each
// account has its own AuthSocket/ProtocolStores/RingRTC CallManager/
// PJSIP Account) now that ringrtc's AUDIO_TRANSPORT global was made
// per-instance (see ~/GIT/vladonv/webrtc/ringrtc/rffi/src/audio_device.cc)
// - two calls on two accounts no longer risk crossing audio.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <thread>

#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <pjmedia/resample.h>
#include <pjsua-lib/pjsua.h>
#include <pjsua2.hpp>

#include "CallSignaling.h"
#include "Config.h"
#include "ContactResolver.h"
#include "StorageServiceSync.h"
#include "../ringrtc/signal2sip_ringrtc.h"
#include "../signal/AuthSocket.h"
#include "../signal/Crypto.h"
#include "../signal/FfiUtil.h"
#include "../signal/PreKeys.h"
#include "../signal/ProtocolStores.h"
#include "../storage/Storage.h"
#include "../util/Base64.h"
#include "../voip/ringrtc_sip_bridge.h"
#include "SignalService.pb.h"

using namespace signal2sip;
using json = nlohmann::json;

namespace {

std::string readFile(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open " + path);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

Bytes b64(const json& j, const char* key) { return base64Decode(j.at(key).get<std::string>()); }

// One-time fallback for this milestone's two already-registered accounts
// (+380000000001, +380000000002) - imports the Node prototype's JSON
// files the exact same way signal_roundtrip_test.cpp's migrateAccount()
// already proved correct. Real gendb-created accounts (Milestone C,
// still not implemented) will never hit this - storage.hasAccount() is
// already true for them.
void migrateFromNodePrototype(Storage& storage, const std::string& e164) {
    std::string base = "/home/vlad/GIT/vladonv/signal2sip/layer1/data/accounts/" + e164;
    json account = json::parse(readFile(base + ".json"));

    AccountRecord record;
    record.e164 = account.at("e164").get<std::string>();
    record.aci = account.at("aci").get<std::string>();
    record.pni = account.at("pni").get<std::string>();
    record.device_id = account.at("deviceId").get<int>();
    record.password = account.at("password").get<std::string>();
    record.registration_id = account.at("registrationId").get<int64_t>();
    record.pni_registration_id = account.at("pniRegistrationId").get<int64_t>();
    storage.saveAccount(record);

    storage.saveIdentityKeypair(
        "aci", IdentityKeypairRecord{b64(account.at("aciIdentityKeyPair"), "privateKey"),
                                     b64(account.at("aciIdentityKeyPair"), "publicKey")});

    const auto& signedPreKey = account.at("aciSignedPreKey");
    storage.saveSignedPrekey("aci",
                              SignedPrekeyRecord{signedPreKey.at("keyId").get<int64_t>(), b64(signedPreKey, "record")});

    const auto& kyberPreKey = account.at("aciPqLastResortPreKey");
    storage.saveKyberPrekey("aci",
                             KyberPrekeyRecord{kyberPreKey.at("keyId").get<int64_t>(), b64(kyberPreKey, "record")});

    // Remote identity trust imports fine (needed for RingRTC's SRTP key
    // derivation - see CallSignaling.cpp's handleCallMessage) - but
    // deliberately NOT importing the double-ratchet session records
    // themselves: found live that a caller's migrated session for the
    // real device (3) plus two stale ones (1, 2 - left over from earlier
    // re-linkings of the same account, both accepted with 200 OK by the
    // server but delivered nowhere) resulted in the callee never
    // receiving anything at all, no error, no envelope, nothing - some
    // combination of stale device fan-out and/or session state
    // divergence between two independently-snapshotted JSON exports
    // (never fully root-caused; not worth it once the fix was obvious).
    // Skipping session import forces CallMessageSender's normal
    // fetchAndEstablishSessions() fallback on the first real send,
    // getting a byte-fresh device list + prekey bundle straight from the
    // server instead of trusting a potentially-stale local cache.
    std::ifstream sessionsFile(base + "-sessions.json");
    if (sessionsFile) {
        json sessions = json::parse(readFile(base + "-sessions.json"));
        for (auto& [address, keyB64] : sessions.at("identities").items()) {
            storage.saveRemoteIdentity(address, base64Decode(keyB64.get<std::string>()));
        }
    }
    std::cout << "[daemon] migrated " << e164 << " from Node prototype JSON files\n";
}

// Generates and uploads fresh signed+Kyber prekeys for both identities,
// saving them to Storage too - matches refresh_prekeys_test.cpp exactly,
// except it also persists locally (that test only uploads, proving the
// server accepts them, since it has no Storage to persist into). Real
// Signal clients do this periodically; this daemon does it once at
// startup, which also fixes a real gap found live: the two test
// accounts' migrated-from-JSON prekeys had drifted from whatever the
// server was actually advertising (stale snapshots from different
// points in time), so a fresh outgoing call's PreKey message failed to
// decrypt on the receiving end ("invalid PreKey message: decryption
// failed") even though the account data itself was otherwise fine.
void refreshPrekeys(Storage& storage, AuthSocket& socket, const AccountRecord& account) {
    int64_t keyId = static_cast<int64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
            .count() %
        0xfffffe);

    auto refreshOne = [&](const char* identity, const Bytes& identityPrivateKey) {
        GeneratedSignedPreKey signedPreKey = generateSignedPreKey(identityPrivateKey, keyId);
        GeneratedKyberPreKey kyberPreKey = generateKyberPreKey(identityPrivateKey, keyId);
        storage.saveSignedPrekey(identity, signedPreKey.stored);
        storage.saveKyberPrekey(identity, kyberPreKey.stored);

        json body = {
            {"preKeys", json::array()},
            {"signedPreKey",
             {{"keyId", signedPreKey.wire.keyId},
              {"publicKey", base64Encode(signedPreKey.wire.publicKey)},
              {"signature", base64Encode(signedPreKey.wire.signature)}}},
            {"pqLastResortPreKey",
             {{"keyId", kyberPreKey.wire.keyId},
              {"publicKey", base64Encode(kyberPreKey.wire.publicKey)},
              {"signature", base64Encode(kyberPreKey.wire.signature)}}},
            {"pqPreKeys", json::array()},
        };
        std::string bodyStr = body.dump();
        Bytes bodyBytes(bodyStr.begin(), bodyStr.end());
        auto response = socket.request("PUT", std::string("/v2/keys?identity=") + identity, &bodyBytes);
        std::cout << "[daemon] PUT /v2/keys?identity=" << identity << " -> " << response.status << "\n";
    };

    auto aciKeypair = storage.loadIdentityKeypair("aci");
    auto pniKeypair = storage.loadIdentityKeypair("pni");
    if (aciKeypair) refreshOne("aci", aciKeypair->private_key);
    if (pniKeypair) refreshOne("pni", pniKeypair->private_key);
}

// Ordered, off-service-thread dispatch for work triggered by onPush() -
// incoming CallMessage handling and DecryptionErrorMessage replies. Both
// used to be a raw `std::thread(...).detach()` per envelope: that
// avoided running on AuthSocket's single service thread (necessary - see
// ProtocolStores::mutex()'s doc comment for the self-deadlock that
// causes), but had three real problems found live: (1) no ordering
// between envelopes, so a same-call ICE-candidate envelope's thread could
// finish before an earlier Offer envelope's thread, and RingRTC would
// drop the ICE candidate for a call it doesn't know about yet; (2)
// unbounded thread creation under a burst/flood of envelopes; (3) nothing
// tracked these threads, so a detached thread could still be running
// when main() destroyed the objects it dereferences, a genuine
// use-after-free on shutdown. A single worker thread with a FIFO queue
// fixes all three: one thread total, strict arrival order, and something
// concrete for shutdown to join. One instance per account (not shared) -
// keeps each account's ordering/shutdown guarantees independent, with
// zero new cross-account interaction to reason about.
class EnvelopeDispatchQueue {
public:
    void start() {
        worker_ = std::thread([this] { run(); });
    }

    void push(std::function<void()> work) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push_back(std::move(work));
        }
        cv_.notify_one();
    }

    // Drains whatever's queued, stops, and joins the worker - call once
    // from main()'s shutdown sequence, before destroying anything queued
    // work might reference.
    void stopAndJoin() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        cv_.notify_one();
        if (worker_.joinable()) worker_.join();
    }

private:
    void run() {
        while (true) {
            std::function<void()> work;
            {
                std::unique_lock<std::mutex> lock(mutex_);
                cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (queue_.empty()) {
                    if (stopping_) return;
                    continue;
                }
                work = std::move(queue_.front());
                queue_.pop_front();
            }
            try {
                work();
            } catch (const std::exception& e) {
                std::cerr << "[daemon] envelope dispatch: unhandled exception: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "[daemon] envelope dispatch: unhandled non-standard exception\n";
            }
        }
    }

    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> queue_;
    bool stopping_ = false;
    std::thread worker_;
};

// Everything one account's C-ABI callbacks (plain function pointers, no
// captures - RingRTC's Signal2sipCallbacks::context carries the pointer
// back to the right instance instead) need. One of these per configured
// account, owned by g_accounts below - replaces what used to be a single
// global DaemonState (one process = one account, pre-refactor).
struct AccountState {
    AccountConfig config;
    std::unique_ptr<Storage> storage;
    std::unique_ptr<ProtocolStores> stores;
    AccountRecord account;
    std::string localServiceId; // == account.aci
    std::unique_ptr<AuthSocket> socket;
    std::unique_ptr<CallMessageSender> sender;
    Signal2sipCallManagerHandle* handle = nullptr;

    // Set once a call is active - the far end's serviceId, used because
    // RingRTC's callbacks give us remote_peer_id already, but call_state
    // doesn't, and we need it to know who to bridge/probe against.
    std::atomic<uint64_t> activeCallId{0};
    std::atomic<bool> isCallee{false};
    std::string remotePeerId;

    // Only ever one of these is non-null at a time (this project's
    // one-call-at-a-time-per-account scope, matching RingRTC's own
    // single-active-call-per-CallManager design) - a second account can
    // still have its own call active concurrently, see this file's
    // top-of-file comment.
    std::unique_ptr<voip::RingRtcSipBridge> bridge;
    pj::Call* sipCall = nullptr; // BridgeCall - we're bridging OUT to the PBX

    // IncomingSipCall - a real SIP INVITE arrived FROM the PBX and we're
    // placing/running an outgoing Signal call in response (opposite
    // direction from sipCall above; still only one of the two at a time,
    // same one-call-per-account scope).
    pj::Call* incomingSipCall = nullptr;

    EnvelopeDispatchQueue dispatchQueue;
};

std::map<std::string, std::unique_ptr<AccountState>> g_accounts; // keyed by AccountConfig::name

// --- RingRTC -> Signal CallMessage (send side) ---

// RingRTC (Rust) invokes these directly and synchronously - a C++
// exception unwinding out of one of them crosses into Rust stack frames,
// which Rust cannot handle ("Rust cannot catch foreign exceptions") and
// hard-aborts the whole process instead of failing just this one call.
// Found live: a transient send failure (e.g. a rate-limited /v2/keys
// fetch inside sendCallMessage's session-establishment fallback) took
// the entire daemon down instead of just that one signaling message.
// Every callback RingRTC calls into must therefore catch everything
// itself (including non-std::exception types - the boundary contract is
// "nothing ever crosses it", not just the common case); on failure,
// simply not calling signal2sip_call_message_sent() leaves RingRTC to
// retry/timeout the call on its own (it has its own ~60s per-call
// timeout independent of this), same as if the message had been lost in
// transit.
template <typename F>
void safeCallback(const char* name, F&& f) {
    try {
        f();
    } catch (const std::exception& e) {
        std::cerr << "[daemon] " << name << " failed: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "[daemon] " << name << " failed: unknown exception\n";
    }
}

void onSendOffer(void* context, const char* remotePeerId, uint64_t callId, int32_t mediaType, const uint8_t* opaque,
                   size_t opaqueLen) {
    auto& acct = *static_cast<AccountState*>(context);
    std::cout << "[daemon][" << acct.config.name << "] send_offer -> " << remotePeerId << "\n";
    safeCallback("send_offer", [&] {
        acct.sender->sendOffer(remotePeerId, callId, mediaType, opaque, opaqueLen);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

void onSendAnswer(void* context, const char* remotePeerId, uint64_t callId, const uint8_t* opaque, size_t opaqueLen) {
    auto& acct = *static_cast<AccountState*>(context);
    std::cout << "[daemon][" << acct.config.name << "] send_answer -> " << remotePeerId << "\n";
    safeCallback("send_answer", [&] {
        acct.sender->sendAnswer(remotePeerId, callId, opaque, opaqueLen);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

void onSendIce(void* context, const char* remotePeerId, uint64_t callId, bool hasReceiverDeviceId,
                uint32_t receiverDeviceId, const uint8_t* opaque, size_t opaqueLen) {
    auto& acct = *static_cast<AccountState*>(context);
    safeCallback("send_ice", [&] {
        acct.sender->sendIce(remotePeerId, callId, hasReceiverDeviceId, receiverDeviceId, opaque, opaqueLen);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

void onSendHangup(void* context, const char* remotePeerId, uint64_t callId, int32_t hangupType,
                   uint32_t hangupDeviceId) {
    auto& acct = *static_cast<AccountState*>(context);
    std::cout << "[daemon][" << acct.config.name << "] send_hangup -> " << remotePeerId << "\n";
    safeCallback("send_hangup", [&] {
        acct.sender->sendHangup(remotePeerId, callId, hangupType, hangupDeviceId);
        signal2sip_call_message_sent(acct.handle, callId);
    });
}

// --- SIP bridging (mirrors pjsip_ringrtc_echo_test.cpp's BridgeCall) ---

// Shared by BridgeCall and IncomingSipCall's onCallMediaState - identical
// resample-port wiring regardless of which direction the SIP leg is
// going. Non-resampling PJSIP conference bridge in this build - see
// pjsip_ringrtc_echo_test.cpp's onCallMediaState for the full story
// (real 488 Not Acceptable Here forcing 48kHz against DPDZK's *43, this
// resample-port approach is the fix that works for any call regardless
// of negotiated codec).
void wireBridgeAudio(pj::Call& call, voip::RingRtcSipBridge& bridge) {
    pj::CallInfo ci = call.getInfo();
    for (unsigned i = 0; i < ci.media.size(); i++) {
        if (ci.media[i].type != PJMEDIA_TYPE_AUDIO || !call.getMedia(i)) continue;
        auto* aud = static_cast<pj::AudioMedia*>(call.getMedia(i));
        unsigned callRate = aud->getPortInfo().format.clockRate;
        std::cout << "[daemon][sip] call clock rate: " << callRate << "\n";

        pj_pool_t* pool = pjsua_pool_create("resample", 2048, 512);
        pjmedia_port* inResample = nullptr;
        pjmedia_resample_port_create(pool, bridge.InputPjmediaPort(), callRate, 0, &inResample);
        pjsua_conf_port_id inResampleId = PJSUA_INVALID_ID;
        pjsua_conf_add_port(pool, inResample, &inResampleId);
        pjsua_conf_connect(aud->getPortId(), inResampleId);

        pjmedia_port* outResample = nullptr;
        pjmedia_resample_port_create(pool, bridge.OutputPjmediaPort(), callRate, 0, &outResample);
        pjsua_conf_port_id outResampleId = PJSUA_INVALID_ID;
        pjsua_conf_add_port(pool, outResample, &outResampleId);
        pjsua_conf_connect(outResampleId, aud->getPortId());

        std::cout << "[daemon][sip] audio wired to RingRtcSipBridge via resample ports\n";
        bridge.Start();
    }
}

class BridgeCall : public pj::Call {
public:
    // `acct` lets onCallState() reach back into the Signal-side call (see
    // its own doc comment below) - only meaningful for an incoming-bridge
    // BridgeCall (startSipDial()'s caller), not for any future
    // outgoing-direction use of this class.
    BridgeCall(pj::Account& acc, voip::RingRtcSipBridge& bridge, AccountState& acct)
        : pj::Call(acc), bridge_(bridge), acct_(acct) {}

    void onCallState(pj::OnCallStateParam&) override {
        pj::CallInfo ci = getInfo();
        std::cout << "[daemon][sip] call state=" << ci.stateText << " (" << ci.state << ")\n";
        // This is the actual moment the PBX side (a real extension/queue/
        // IVR) picked up - only now do we take over the Signal call. See
        // startSipDial()'s doc comment for why this is deliberately late
        // (not right after Signal's own Ringing) - the whole point is to
        // let a real linked device win the race if a human answers it
        // first, and only "steal" the call once the PBX side has
        // genuinely answered. acceptSent_ guards against PJSIP possibly
        // reporting CONFIRMED more than once for the same dialog.
        if (ci.state == PJSIP_INV_STATE_CONFIRMED && !acceptSent_.exchange(true)) {
            std::cout << "[daemon][" << acct_.config.name
                       << "][sip] PBX answered - accepting the Signal call\n";
            signal2sip_call_accept(acct_.handle, acct_.activeCallId.load());
        }
        if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
            // If we'd actually taken over the Signal call (acceptSent_)
            // and this disconnect wasn't us hanging up first (weHungUp_,
            // set by stopSipBridge() right before its own call->hangup())
            // then the PBX side hung up on its own - found live 2026-08-05:
            // without this, ending the call on the PBX side left the
            // Signal call sitting CONNECTED forever on the caller's
            // Android, since nothing ever told RingRTC this side was
            // done. hangup() ends whatever call_manager's current active
            // call is; the ENDED/CONCLUDED event it triggers is what runs
            // stopSipBridge()'s normal teardown (bridge_.Stop(), deleting
            // this BridgeCall) - so no separate cleanup is needed here.
            if (acceptSent_.load() && !weHungUp_.load()) {
                std::cout << "[daemon][" << acct_.config.name
                           << "][sip] PBX hung up - ending the Signal call\n";
                signal2sip_call_hangup(acct_.handle);
            }
            disconnected_ = true;
        }
    }

    void onCallMediaState(pj::OnCallMediaStateParam&) override { wireBridgeAudio(*this, bridge_); }

    std::atomic<bool> disconnected_{false};
    std::atomic<bool> weHungUp_{false}; // set by stopSipBridge() before its own hangup()

private:
    voip::RingRtcSipBridge& bridge_;
    AccountState& acct_;
    std::atomic<bool> acceptSent_{false};
};

// Handles the opposite direction from BridgeCall: a real SIP INVITE
// arriving AT the daemon (from Asterisk/the PBX) that should place a real
// outgoing Signal call - see BridgeAccount::onIncomingCall's own doc
// comment for how the destination number and originating account get
// picked. Not answered (200 OK) until the outgoing Signal call actually
// reaches CONNECTED (see onCallState's own CONNECTED handler) - kept
// Ringing until then so the caller sees real call progress instead of an
// instant, possibly-wrong answer.
class IncomingSipCall : public pj::Call {
public:
    IncomingSipCall(pj::Account& acc, int callId, voip::RingRtcSipBridge& bridge, AccountState& acct)
        : pj::Call(acc, callId), bridge_(bridge), acct_(acct) {}

    void onCallState(pj::OnCallStateParam&) override {
        pj::CallInfo ci = getInfo();
        std::cout << "[daemon][sip] incoming call state=" << ci.stateText << " (" << ci.state << ")\n";
        if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
            // Mirrors BridgeCall's own DISCONNECTED handling in the
            // opposite direction: if the PBX/caller hung up or cancelled
            // and this wasn't us hanging up first (weHungUp_, set by
            // stopIncomingSipCall() before its own hangup()), end
            // whatever the outgoing Signal call attempt is doing too -
            // otherwise a caller hanging up before the Signal side ever
            // answers would leave that outgoing call ringing forever.
            if (!weHungUp_.exchange(true)) {
                signal2sip_call_hangup(acct_.handle);
            }
            disconnected_ = true;
        }
    }

    void onCallMediaState(pj::OnCallMediaStateParam&) override { wireBridgeAudio(*this, bridge_); }

    std::atomic<bool> disconnected_{false};
    std::atomic<bool> weHungUp_{false}; // set by stopIncomingSipCall() before its own hangup()

private:
    voip::RingRtcSipBridge& bridge_;
    AccountState& acct_;
};

class BridgeAccount : public pj::Account {
public:
    std::atomic<bool> registered{false};

    // Set right after construction in setupAccount(), before this account
    // can possibly receive any real SIP traffic - lets onIncomingCall()
    // (defined out-of-line below, after g_global's declaration) know
    // which Signal identity received the INVITE, so it knows which
    // account to originate the resulting outgoing Signal call from.
    AccountState* acctState = nullptr;

    // Defined out-of-line after g_global (needed for
    // resolvedContactTtlSec) - see its own doc comment there for the
    // full "why".
    void onIncomingCall(pj::OnIncomingCallParam& iprm) override;

    // Epoch-ms timestamp of the most recent transition into "not
    // registered" (0 while currently registered) - read by the
    // registration watchdog in main()'s loop to decide when PJSIP's own
    // retry has had enough time and it's worth forcing another attempt
    // ourselves. Not just a bool: PJSIP only auto-retries a short
    // allowlist of "temporary" failure codes (see pjsua_acc.c's regc_cb -
    // 408/500/502/503/504/480/6xx); a 403 Forbidden is not on that list
    // and would otherwise never retry again on its own, confirmed live
    // 08-04 (a stale-contact 403 during testing left the account dead
    // until the whole process was restarted).
    std::atomic<int64_t> unregisteredSinceMs{0};

    void onRegState(pj::OnRegStateParam&) override {
        pj::AccountInfo ai = getInfo();
        std::cout << "[daemon][sip] reg state active=" << ai.regIsActive << "\n";
        // Must mirror regIsActive both ways - PJSIP's own regc retries
        // registration automatically (default 300s interval) after a
        // failure/outage, but until that retry succeeds this flag is
        // startSipDial()'s only signal that the account isn't actually
        // usable right now. Only ever setting it true (never back to
        // false) meant a Signal call arriving mid-outage would still
        // attempt a real INVITE through a dead registration instead of
        // failing cleanly.
        registered = ai.regIsActive;
        if (ai.regIsActive) {
            unregisteredSinceMs = 0;
        } else if (unregisteredSinceMs.load() == 0) {
            unregisteredSinceMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                      std::chrono::steady_clock::now().time_since_epoch())
                                      .count();
        }
    }
};

// One shared PJSIP Endpoint for the whole process (pjsua2/PJSIP itself is
// a process-wide singleton - only one Endpoint is possible per process).
// Every account still gets its OWN dedicated transport off of this one
// Endpoint though (see createAccountUdpTransport()/
// createAccountTlsTransport()) - PJSIP can't reliably route an incoming
// call to the right account when several accounts share one transport
// and the Request-URI doesn't match any of their own identities (see
// AccountConfig::sipTransport's own doc comment for the live bug this
// caused). Created lazily (see ensureSharedEndpoint()) the first time any
// account needs it - either at startup or via a later SIGHUP reload - and
// never destroyed until process exit. Read (never written after
// creation) from startSipDial()'s libRegisterThread() call.
pj::Endpoint* g_ep = nullptr;
std::map<std::string, std::unique_ptr<BridgeAccount>> g_sipAccounts; // keyed by AccountConfig::name

// sipBridgeDid wins if both are somehow set - see AccountConfig's own doc
// comment for why that shouldn't realistically happen (the matching
// Asterisk endpoint only ever has one context, from-internal or
// from-pstn, never both). Empty means this account doesn't bridge
// incoming calls to SIP at all.
const std::string& bridgeTarget(const AccountConfig& config) {
    return config.sipBridgeDid.empty() ? config.sipBridgeDestination : config.sipBridgeDid;
}

// True only if this account both has a bridge target configured AND its
// SIP registration is actually up right now - checked here, BEFORE ever
// answering on the Signal side (see onCallState's INCOMING_AUDIO
// handler), not just inside startSipDial() itself. Confirmed live
// 08-04 that the earlier version of this check (target configured, full
// stop) still steals the Accept from this account's other real devices
// even when Asterisk/the SIP registration is unreachable - the call gets
// answered here, then startSipDial() discovers it can't actually bridge
// and just logs an error, by which point the real devices have already
// lost the race for nothing.
bool canBridgeToSip(const AccountConfig& config) {
    if (bridgeTarget(config).empty()) return false;
    auto it = g_sipAccounts.find(config.name);
    return it != g_sipAccounts.end() && it->second->registered.load();
}

// PJSUA2 requires every thread that calls into it to be registered with
// PJLIB first (Endpoint::libRegisterThread()), unless it's the thread
// that originally initialized the library (main()'s thread, which called
// ep.libCreate()/libInit()/libStart()) or one of PJSIP's own worker
// threads. Every function here that calls into pjsua2 from RingRTC's own
// callback thread (onCallState() and anything it calls, e.g.
// stopSipBridge()/stopIncomingSipCall() from the ENDED/CONCLUDED branch)
// needs this, once per OS thread - found live in startSipDial() first:
// without it, makeCall() still sent a real INVITE (the transport layer
// tolerated the unregistered thread fine), but PJSIP's automatic
// 401-challenge auto-retry - which relies on the dialog's thread-local
// auth session state - never fired, so a real call to DPDZK's *43 got
// exactly one INVITE, one 401, and then silently never connected.
//
// Found live again 2026-08-05, a second time: stopIncomingSipCall() was
// calling call->hangup() from this same unregistered RingRTC callback
// thread - unlike the Signal-call-bridges-to-SIP direction (where
// startSipDial() always runs first for that call, on that same thread,
// and registers it), the SIP-triggers-a-Signal-call direction has no
// earlier pjsua2 call on that thread to register it first. Silently
// broke that account's own SIP registration refresh a few seconds after
// the next failed/timed-out call - not a crash, so it went unnoticed
// until the registration itself quietly expired with nothing to renew
// it (user's own diagnosis: registration died a few seconds after the
// last failed Signal call, and stayed fine indefinitely when no call was
// ever attempted).
void registerPjsipThreadIfNeeded() {
    thread_local bool registered = false;
    if (!registered && g_ep) {
        try {
            g_ep->libRegisterThread("ringrtc-callback");
        } catch (pj::Error& err) {
            std::cerr << "[daemon] libRegisterThread failed: " << err.info() << "\n";
        }
        registered = true;
    }
}

// Places an outbound SIP INVITE to bridgeTarget(acct.config) - called at
// the incoming Signal call's Ringing state, deliberately BEFORE that
// Signal call is ever accepted on this device. This is what lets the SIP
// leg ring/queue/IVR on the PBX side as an independent participant in the
// account's normal multi-device fan-out, racing fairly against a real
// linked device (phone, Desktop, ...) instead of the daemon eagerly
// accepting the instant it's willing to bridge at all - the earlier
// version of this code called signal2sip_call_accept() right after
// Ringing, unconditionally, which (being near-instant) always beat a
// human tapping Accept on their phone (see
// [[project_signal2sip_incoming_call_steals_accept_bug]] in memory for
// that first version of the problem - this is the same race, one layer
// deeper: even gated on canBridgeToSip(), accepting before the PBX side
// has actually answered still steals the call for a bridge attempt that
// might itself go unanswered). BridgeCall::onCallState() is what actually
// calls signal2sip_call_accept(), once and only once the SIP INVITE
// reaches PJSIP_INV_STATE_CONFIRMED - i.e. once a real person/queue/IVR
// on the PBX side has genuinely picked up.
void startSipDial(AccountState& acct) {
    auto it = g_sipAccounts.find(acct.config.name);
    if (it == g_sipAccounts.end() || !it->second->registered.load()) {
        std::cerr << "[daemon][" << acct.config.name << "] cannot bridge to SIP: not registered\n";
        return;
    }
    BridgeAccount& sipAccount = *it->second;

    registerPjsipThreadIfNeeded();

    acct.bridge = std::make_unique<voip::RingRtcSipBridge>(acct.handle);

    // Real, pre-existing bug found live 08-04: this always used "sip:"
    // regardless of transport, unlike acfg.idUri/regConfig.registrarUri
    // above (built with the correct sips:-for-tls scheme) - a plain
    // "sip:" request URI tells PJSIP this call's security_level is 0,
    // which PJSIP_ESESSIONINSECURE's own check (pjsua_media.c:
    // "security_level < acc->cfg.srtp_secure_signaling") then correctly
    // rejects for any account that left srtp_secure_signaling at its
    // real default of 1 (every sip_transport=tls account here, since
    // main.cpp only ever relaxes that default for non-tls accounts).
    std::string scheme = acct.config.sipTransport == "tls" ? "sips" : "sip";
    std::string destUri = scheme + ":" + bridgeTarget(acct.config) + "@" + acct.config.sipHost;
    std::cout << "[daemon][" << acct.config.name << "][sip] placing bridge call to " << destUri << "\n";
    auto* call = new BridgeCall(sipAccount, *acct.bridge, acct);
    acct.sipCall = call;
    pj::CallOpParam prm(true);
    prm.opt.audioCount = 1;
    prm.opt.videoCount = 0;
    try {
        call->makeCall(destUri, prm);
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << acct.config.name << "] FAIL: makeCall: " << err.info() << "\n";
    }
}

void stopSipBridge(AccountState& acct) {
    registerPjsipThreadIfNeeded();
    if (acct.bridge) {
        acct.bridge->Stop();
    }
    if (acct.sipCall) {
        auto* call = static_cast<BridgeCall*>(acct.sipCall);
        call->weHungUp_ = true; // before hangup() - see onCallState's DISCONNECTED handling
        pj::CallOpParam hprm;
        try {
            call->hangup(hprm);
        } catch (...) {
        }
        for (int i = 0; i < 50 && !call->disconnected_.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        delete call;
        acct.sipCall = nullptr;
    }
    acct.bridge.reset();
}

// Mirrors stopSipBridge() for the opposite direction (IncomingSipCall
// instead of BridgeCall) - see AccountState::incomingSipCall's own doc
// comment. acct.bridge is the same shared field either function may have
// populated; harmless no-op here if the OTHER direction is what's
// actually active (acct.bridge already null, guard below just skips).
void stopIncomingSipCall(AccountState& acct) {
    registerPjsipThreadIfNeeded();
    if (acct.bridge) {
        acct.bridge->Stop();
    }
    if (acct.incomingSipCall) {
        auto* call = static_cast<IncomingSipCall*>(acct.incomingSipCall);
        call->weHungUp_ = true; // before hangup() - see onCallState's DISCONNECTED handling
        pj::CallOpParam hprm;
        try {
            call->hangup(hprm);
        } catch (...) {
        }
        for (int i = 0; i < 50 && !call->disconnected_.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        delete call;
        acct.incomingSipCall = nullptr;
    }
    acct.bridge.reset();
}

// --- Outgoing-call test probe (mirrors pjsip_ringrtc_echo_test.cpp's peerA) ---

void runProbe(AccountState& acct) {
    const int sampleRate = 48000;
    const int toneHz = 440;
    const int totalSamples = sampleRate * 10;
    std::vector<int16_t> tone(totalSamples);
    for (int i = 0; i < totalSamples; i++) {
        tone[i] = static_cast<int16_t>(8000.0 * std::sin(2.0 * M_PI * toneHz * i / sampleRate));
    }
    std::vector<int16_t> received;
    received.reserve(totalSamples * 2);
    const int chunk = 480;
    for (int offset = 0; offset < totalSamples; offset += chunk) {
        int n = std::min(chunk, totalSamples - offset);
        signal2sip_push_recorded_samples(acct.handle, tone.data() + offset, n);
        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(acct.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "[daemon][" << acct.config.name << "][probe] pulled " << received.size() << " samples\n";
    double sumSquares = 0;
    for (int16_t s : received) sumSquares += static_cast<double>(s) * s;
    double rms = received.empty() ? 0.0 : std::sqrt(sumSquares / received.size());
    std::cout << "[daemon][" << acct.config.name << "][probe] RMS of received (echoed) audio: " << rms << "\n";
    bool audioFlowed = received.size() > static_cast<size_t>(sampleRate) && rms > 20.0;
    std::cout << "[daemon][" << acct.config.name << "] " << (audioFlowed ? "PASS" : "FAIL")
               << ": tone round-tripped through the real Signal call + remote's SIP bridge\n";

    signal2sip_call_hangup(acct.handle);
}

// --- RingRTC call state machine ---

void onCallState(void* context, const char* remotePeerId, uint64_t callId, int32_t state) {
    auto& acct = *static_cast<AccountState*>(context);
    acct.activeCallId = callId;
    acct.remotePeerId = remotePeerId;
    std::cout << "[daemon][" << acct.config.name << "] call_state -> " << state << " (peer " << remotePeerId
               << ")\n";

    // Called synchronously from RingRTC (Rust) - same FFI-exception-safety
    // reasoning as the onSend* callbacks above.
    safeCallback("onCallState", [&] {
        if (state == SIGNAL2SIP_CALL_STATE_OUTGOING_AUDIO) {
            signal2sip_call_proceed(acct.handle, callId);
        } else if (state == SIGNAL2SIP_CALL_STATE_INCOMING_AUDIO) {
            // Only proceed (which answers the call, on THIS device, right
            // now) if there's an actual, currently-reachable SIP
            // destination to bridge it to (see canBridgeToSip's own doc
            // comment) - proceeding otherwise just steals the Accept from
            // this account's other real devices (a linked phone, Signal
            // Desktop, ...) before they even get a chance to ring, for a
            // bridge that either doesn't exist or was never going to work
            // anyway. Confirmed live 08-04: an account with neither bridge
            // field set auto-accepted every incoming call into a null
            // audio device, and the user's own real phone (a linked
            // device on the same account) got "AcceptedOnAnotherDevice" -
            // this device had already answered first. Leaving state
            // untouched here means this device simply never answers, same
            // as never having this account open at all - the call rings
            // through to the account's other devices normally, exactly
            // like any other idle Signal client that never calls
            // proceed()/accept().
            if (canBridgeToSip(acct.config)) {
                acct.isCallee = true;
                signal2sip_call_proceed(acct.handle, callId);
            }
        } else if (state == SIGNAL2SIP_CALL_STATE_RINGING && acct.isCallee.load()) {
            // Used to call signal2sip_call_accept() right here (see
            // signal2sip_call_accept()'s own doc comment for why it's only
            // legal after Ringing, never right after proceed()) - but
            // doing so unconditionally meant the daemon always won the
            // multi-device accept race the instant it was willing to
            // bridge at all, before the PBX side had even been dialed,
            // let alone answered (confirmed live 2026-08-05: calling
            // +123456789002 from another Signal account, the daemon
            // intercepted the call immediately and the real linked phone
            // never got a chance to ring). Re-checking canBridgeToSip()
            // here mirrors the same re-check this branch used to do at
            // CONNECTED, in case registration dropped between Proceed and
            // Ringing. Accepting now happens in BridgeCall::onCallState()
            // once the SIP leg placed by startSipDial() actually reaches
            // PJSIP_INV_STATE_CONFIRMED - i.e. once the PBX side has
            // genuinely answered - so a real linked device tapping Accept
            // first still wins normally.
            if (canBridgeToSip(acct.config)) {
                startSipDial(acct);
            }
        } else if (state == SIGNAL2SIP_CALL_STATE_CONNECTED) {
            // The isCallee branch that used to live here (calling
            // startSipBridge() once Signal was Accepted) is gone - the SIP
            // leg is now dialed earlier, at Ringing, and BridgeCall's own
            // onCallMediaState() wires+starts the bridge independently
            // once the SIP side has media, regardless of exactly when
            // Signal's own CONNECTED fires relative to that.
            if (!acct.isCallee.load() && acct.incomingSipCall) {
                // The mirror image of the above: a real SIP call is
                // sitting in Ringing (BridgeAccount::onIncomingCall()
                // placed it, never answered) waiting on exactly this
                // moment - the outgoing Signal call it triggered just
                // connected, so answer it now. IncomingSipCall's own
                // onCallMediaState() wires+starts the bridge once this
                // 200 OK's SDP answer negotiates media, same as the
                // BridgeCall side. registerPjsipThreadIfNeeded() matters
                // here too - this runs on RingRTC's own callback thread,
                // same as stopSipBridge()/stopIncomingSipCall() (see that
                // function's own doc comment for the live bug this fixes).
                registerPjsipThreadIfNeeded();
                auto* sipCall = static_cast<IncomingSipCall*>(acct.incomingSipCall);
                pj::CallOpParam ansPrm;
                ansPrm.statusCode = PJSIP_SC_OK;
                try {
                    sipCall->answer(ansPrm);
                } catch (pj::Error& err) {
                    std::cerr << "[daemon][" << acct.config.name << "][sip] answer(200) failed: " << err.info()
                               << "\n";
                }
            } else if (!acct.isCallee.load() && !acct.config.outgoingCallTarget.empty()) {
                std::thread([&acct] { runProbe(acct); }).detach();
            }
        } else if (state == SIGNAL2SIP_CALL_STATE_ENDED || state == SIGNAL2SIP_CALL_STATE_CONCLUDED) {
            stopSipBridge(acct);
            stopIncomingSipCall(acct);
            acct.isCallee = false;
        }
    });
}

Signal2sipCallbacks makeCallbacks(AccountState& acct) {
    Signal2sipCallbacks cb{};
    cb.context = &acct;
    cb.send_offer = onSendOffer;
    cb.send_answer = onSendAnswer;
    cb.send_ice = onSendIce;
    cb.send_hangup = onSendHangup;
    cb.call_state = onCallState;
    return cb;
}

// --- Incoming envelope handling ---

void onPush(AccountState& acct, const std::string& verb, const std::string& path, const Bytes& body) {
    if (verb != "PUT" || path != "/api/v1/message" || body.empty()) return;

    signalservice::Envelope envelope;
    if (!envelope.ParseFromArray(body.data(), static_cast<int>(body.size()))) {
        std::cerr << "[daemon][" << acct.config.name << "] failed to parse pushed Envelope\n";
        return;
    }

    Bytes plaintext;
    std::string senderServiceId;
    uint32_t senderDeviceId = 0;
    // Only meaningful for the DOUBLE_RATCHET/PREKEY_MESSAGE branch below -
    // captured before the decrypt attempt so they're still available in
    // the catch block to build a DecryptionErrorMessage reply.
    bool isIdentifiedCiphertext = false;
    Bytes originalCiphertext;
    uint8_t originalMessageType = 0;

    try {
        // Same lock CallMessageSender::sendCallMessage takes - this runs
        // on the websocket read thread, which can otherwise race an
        // outgoing send's session-store mutation on RingRTC's callback
        // thread (see ProtocolStores::mutex()).
        std::lock_guard<std::mutex> lock(acct.stores->mutex());
        if (envelope.type() == signalservice::Envelope_Type_UNIDENTIFIED_SENDER) {
            Bytes ciphertext(envelope.content().begin(), envelope.content().end());
            SealedSenderResult result =
                decryptSealedSender(*acct.stores, Address{acct.localServiceId, static_cast<uint32_t>(acct.account.device_id)},
                                    ciphertext, envelope.servertimestamp());
            plaintext = result.plaintext;
            senderServiceId = result.senderServiceId;
            senderDeviceId = result.senderDeviceId;
        } else if (envelope.type() == signalservice::Envelope_Type_DOUBLE_RATCHET ||
                   envelope.type() == signalservice::Envelope_Type_PREKEY_MESSAGE) {
            senderServiceId = resolveServiceId(envelope.sourceserviceidbinary());
            senderDeviceId = envelope.sourcedeviceid();
            isIdentifiedCiphertext = true;
            originalMessageType = envelope.type() == signalservice::Envelope_Type_PREKEY_MESSAGE
                                        ? SignalCiphertextMessageTypePreKey
                                        : SignalCiphertextMessageTypeWhisper;
            originalCiphertext.assign(envelope.content().begin(), envelope.content().end());
            plaintext = decryptCiphertext(*acct.stores,
                                          Address{acct.localServiceId, static_cast<uint32_t>(acct.account.device_id)},
                                          Address{senderServiceId, senderDeviceId}, originalMessageType,
                                          originalCiphertext);
        } else {
            return; // receipt/other envelope type - nothing to decrypt
        }
    } catch (const std::exception& e) {
        std::cerr << "[daemon][" << acct.config.name << "] failed to decrypt envelope: " << e.what() << "\n";
        // Real Signal Protocol recovery: tell the sender so its own
        // client can detect the desync and fall back to a fresh PreKey
        // handshake, instead of this failing silently forever every time
        // (see CallSignaling.h's sendDecryptionErrorReply() doc comment -
        // found live against a real phone's already-desynced session
        // with no other way to recover it). Only meaningful for
        // identified (non-sealed-sender) ciphertext, where we know who
        // sent it and have the raw bytes needed to build the reply; a
        // sealed-sender envelope whose outer unseal itself failed gives
        // us neither.
        if (isIdentifiedCiphertext && !senderServiceId.empty()) {
            // sendDecryptionErrorReply() manages its own (narrow, never
            // held across network I/O) locking internally - see its
            // definition - so no lock is taken here.
            acct.dispatchQueue.push([&acct, senderServiceId, senderDeviceId, originalCiphertext, originalMessageType,
                                     clientTimestamp = envelope.clienttimestamp()] {
                sendDecryptionErrorReply(*acct.socket, *acct.stores, *acct.sender, acct.localServiceId,
                                         static_cast<uint32_t>(acct.account.device_id), senderServiceId,
                                         senderDeviceId, originalCiphertext, originalMessageType, clientTimestamp);
            });
        }
        return;
    }

    std::cout << "[daemon][" << acct.config.name << "][diag] decrypted envelope from " << senderServiceId
               << " device " << senderDeviceId << " (" << plaintext.size() << " bytes plaintext)\n";

    signalservice::Content content;
    if (!content.ParseFromArray(plaintext.data(), static_cast<int>(plaintext.size()))) {
        std::cerr << "[daemon][" << acct.config.name << "] failed to parse decrypted Content\n";
        return;
    }
    if (content.has_datamessage()) {
        std::cout << "[daemon][" << acct.config.name << "][diag] DataMessage body: " << content.datamessage().body()
                   << "\n";
    }
    if (!content.has_callmessage()) return;

    std::cout << "[daemon][" << acct.config.name << "] CallMessage from " << senderServiceId << " device "
               << senderDeviceId << "\n";

    // Must not call handleCallMessage() directly on this thread: it's
    // AuthSocket's single serviceThread (the one running lws_service()),
    // and RingRTC can synchronously invoke a send_offer/send_answer/
    // send_ice callback in reaction to this incoming CallMessage. Those
    // callbacks block on AuthSocket::request() waiting for a response -
    // but the response can only ever be delivered by this same thread's
    // lws_service() loop, which can't run again until this call stack
    // unwinds. That's a guaranteed self-deadlock (observed live as
    // "PUT /v1/messages ... timed out waiting for a response" exactly
    // 30s later, intermittently - only when RingRTC happened to react
    // synchronously rather than via its own actor thread). Dispatching
    // via the ordered queue (see EnvelopeDispatchQueue) keeps this
    // thread free to keep servicing the socket, while still processing
    // envelopes in arrival order and giving shutdown something to join.
    signalservice::CallMessage callMessage = content.callmessage();
    uint32_t localDeviceId = static_cast<uint32_t>(acct.account.device_id);
    acct.dispatchQueue.push([&acct, senderServiceId, senderDeviceId, localDeviceId, callMessage] {
        handleCallMessage(acct.handle, *acct.stores, senderServiceId, senderDeviceId, localDeviceId, callMessage);
    });
}

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

// SIGHUP: standard unix "reload config" convention (nginx/postfix etc.) -
// simplest possible trigger, no new control socket/protocol needed. Just
// sets a flag; the actual reload happens on the main thread's own loop
// (reloadConfig() below), never inside the signal handler itself.
std::atomic<bool> g_reloadRequested{false};
void onReloadSignal(int) { g_reloadRequested = true; }

std::string g_configPath; // set once in main(), read by reloadConfig()
GlobalConfig g_global;    // set once in main() from config.global, read by setupAccount()

// Creates the shared Endpoint the first time any account needs it - either
// during main()'s startup loop, or later via a SIGHUP reload adding the
// first-ever SIP-enabled account to a daemon that started with none. Does
// NOT create any transport itself anymore - every account gets its own
// dedicated one (see createAccountUdpTransport()/
// createAccountTlsTransport(), both called from setupAccount()).
// `epStorage` is function-static (not a main()-local variable) specifically
// so it survives past the point where main()'s own startup code has
// finished running, in case this is called again later from reloadConfig().
void ensureSharedEndpoint() {
    if (g_ep) return; // already created

    static std::unique_ptr<pj::Endpoint> epStorage;
    epStorage = std::make_unique<pj::Endpoint>();
    try {
        epStorage->libCreate();
        pj::EpConfig epConfig;
        epConfig.medConfig.ecTailLen = 0;
        epConfig.medConfig.noVad = true;
        // 10ms ptime required to keep an uncompressed L16 RTP packet
        // below the MTU (tg2sip-webrtc/tg2sip/sip.cpp's own comment).
        epConfig.medConfig.audioFramePtime = 10;
        epConfig.medConfig.ptime = 10;
        epConfig.medConfig.clockRate = 48000;
        epStorage->libInit(epConfig);
        epStorage->audDevManager().setNullDev();

        // Force L16/48000/1 (raw PCM, mono) as the only codec PJSIP will
        // ever offer/accept, matching RingRtcSipBridge's fixed format
        // exactly - same technique as tg2sip-webrtc's ep.codecSetPriority()
        // loop. codecEnum() (returning CodecInfoVector, a vector of
        // pointers) is gone in this PJSIP version - only codecEnum2()
        // (CodecInfoVector2, a vector of values) remains; see
        // native/CMakeLists.txt's PJPROJECT_DIR comment for why this
        // project moved off PJSIP 2.9.
        for (const auto& codec : epStorage->codecEnum2()) {
            epStorage->codecSetPriority(codec.codecId, codec.codecId == "L16/48000/1" ? 255 : 0);
        }

        epStorage->libStart();
        g_ep = epStorage.get();
    } catch (pj::Error& err) {
        std::cerr << "[daemon] SIP Endpoint setup failed: " << err.info() << "\n";
        epStorage.reset();
        g_ep = nullptr;
    }
}

// Creates a UDP transport dedicated to ONE account. Local port 0 (OS
// picks any free ephemeral port) - Asterisk always dials back to
// whatever Contact this account's own registration advertised, so the
// exact port doesn't need to be predictable, same reasoning as
// createAccountTlsTransport()'s own port 0. Returns pj::PJSUA_INVALID_ID
// on failure (logged there, caller just won't get a working account).
// Requires g_ep to already exist (ensureSharedEndpoint() must run first).
pj::TransportId createAccountUdpTransport(const AccountConfig& accountConfig) {
    if (!g_ep) return PJSUA_INVALID_ID;

    try {
        pj::TransportConfig tcfg;
        tcfg.port = 0;
        pj::TransportId id = g_ep->transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
        std::cout << "[daemon][" << accountConfig.name << "] UDP transport created\n";
        return id;
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << accountConfig.name << "] UDP transport setup failed: " << err.info() << "\n";
        return PJSUA_INVALID_ID;
    }
}

// Creates a TLS (SIPS) transport dedicated to ONE account - PJSIP's TLS
// trust settings (CaListFile/verifyServer) are configured once per
// transport factory and apply to every connection made through it, so two
// accounts pointing at two different Asterisk hosts with two different
// (self-signed) certificates genuinely need their own transport each -
// see AccountConfig::sipTlsCaFile's own doc comment. Local port 0 (OS
// picks any free port) is fine here - TLS/TCP is connection-oriented, so
// Asterisk calls back over the same persistent connection this process
// already opened for registration, unlike UDP where a specific advertised
// port matters. Returns pj::PJSUA_INVALID_ID on failure. Requires g_ep to
// already exist (ensureSharedEndpoint() must run first).
pj::TransportId createAccountTlsTransport(const AccountConfig& accountConfig) {
    if (!g_ep) return PJSUA_INVALID_ID;

    try {
        pj::TransportConfig tcfg;
        tcfg.port = 0;
        // PJSIP's own default TLS method is the ancient PJSIP_TLSV1_METHOD
        // (TLS 1.0) - found live that Asterisk's transport-tls rejects
        // that outright (TLSV1_ALERT_PROTOCOL_VERSION). Restrict to modern
        // versions explicitly instead of relying on the default.
        tcfg.tlsConfig.proto = PJ_SSL_SOCK_PROTO_TLS1_2 | PJ_SSL_SOCK_PROTO_TLS1_3;
        if (!accountConfig.sipTlsCaFile.empty()) {
            tcfg.tlsConfig.CaListFile = accountConfig.sipTlsCaFile;
            tcfg.tlsConfig.verifyServer = true;
        } else {
            // Config::load() already refuses sip_transport=tls with
            // neither sip_tls_ca_file nor sip_tls_insecure=yes set, so
            // reaching here with an empty CaListFile means the operator
            // explicitly opted into this.
            tcfg.tlsConfig.verifyServer = false;
        }
        pj::TransportId id = g_ep->transportCreate(PJSIP_TRANSPORT_TLS, tcfg);
        std::cout << "[daemon][" << accountConfig.name << "] TLS transport created"
                   << (accountConfig.sipTlsCaFile.empty() ? " (server cert verification DISABLED - sip_tls_insecure=yes)"
                                                          : " (pinned to " + accountConfig.sipTlsCaFile + ")")
                   << "\n";
        return id;
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << accountConfig.name << "] TLS transport setup failed: " << err.info() << "\n";
        return PJSUA_INVALID_ID;
    }
}

// A real SIP call arrived at this account's registered contact - place a
// real outgoing Signal call in response. Found live 2026-08-05: this
// direction (PBX calls IN to a signal2sip SIP trunk to originate a real
// Signal call out) had no handler at all - pjsua2's default
// Account::onIncomingCall() (i.e. not overriding it) leaves its
// temporary Call wrapper to be destroyed at the end of the callback,
// which itself hangs up with a bare 500 - every such INVITE was silently
// rejected before this existed.
//
// The destination is read from the raw Request-URI's user part (NOT
// this->acctState's own configured number) - confirmed live that
// Asterisk's outbound-route/trunk config for a given destination number
// can point its INVITE at a DIFFERENT account's registered contact than
// that number itself (this test: a trunk for "123456789002" sent its
// INVITE to 123456789004's TLS contact, Request-URI user still
// "123456789002") - so the account that answers is just "whichever
// identity Asterisk chose to send this INVITE from", and the number to
// call is purely whatever's in the Request-URI, regardless of whether
// that number also happens to be one of this daemon's own configured
// accounts (user's own framing: "как обычный сигнал звонок").
void BridgeAccount::onIncomingCall(pj::OnIncomingCallParam& iprm) {
    if (!acctState) {
        // Shouldn't happen - every BridgeAccount is constructed with a
        // matching AccountState in setupAccount() before it can ever
        // register (and therefore before it could receive any INVITE).
        pj::Call tmp(*this, iprm.callId);
        pj::CallOpParam prm;
        prm.statusCode = PJSIP_SC_SERVICE_UNAVAILABLE;
        try {
            tmp.hangup(prm);
        } catch (...) {
        }
        return;
    }
    AccountState& acct = *acctState;
    if (acct.incomingSipCall || acct.sipCall) {
        // Already bridging a call in one direction or the other -
        // this project's one-call-at-a-time-per-account scope (see
        // AccountState::bridge's own doc comment).
        pj::Call tmp(*this, iprm.callId);
        pj::CallOpParam prm;
        prm.statusCode = PJSIP_SC_BUSY_HERE;
        try {
            tmp.hangup(prm);
        } catch (...) {
        }
        return;
    }

    std::string destUser;
    auto* rdata = static_cast<pjsip_rx_data*>(iprm.rdata.pjRxData);
    if (rdata && rdata->msg_info.msg) {
        pjsip_uri* reqUri = rdata->msg_info.msg->line.req.uri;
        if (PJSIP_URI_SCHEME_IS_SIP(reqUri) || PJSIP_URI_SCHEME_IS_SIPS(reqUri)) {
            auto* sipUri = static_cast<pjsip_sip_uri*>(pjsip_uri_get_uri(reqUri));
            destUser.assign(sipUri->user.ptr, sipUri->user.slen);
        }
    }
    // Request-URI user parts are plain digits by SIP convention (no '+'),
    // but resolveOutgoingTarget()/ContactResolver.cpp only treats a target
    // as a phone number needing CDSI resolution when it starts with '+' -
    // anything else is assumed to already be a ServiceId. Found live
    // 2026-08-05: without this, a bare "123456789001" from Asterisk's
    // INVITE skipped CDSI entirely and got used as-is, so RingRTC tried
    // fetching prekeys from "GET /v2/keys/123456789001/*" - a phone
    // number, not a real ServiceId UUID - and always 404'd.
    if (!destUser.empty() && destUser[0] != '+') {
        destUser.insert(0, "+");
    }
    std::cout << "[daemon][" << acct.config.name << "][sip] incoming SIP call for '" << destUser << "'\n";
    if (destUser.empty()) {
        pj::Call tmp(*this, iprm.callId);
        pj::CallOpParam prm;
        prm.statusCode = PJSIP_SC_NOT_FOUND;
        try {
            tmp.hangup(prm);
        } catch (...) {
        }
        return;
    }

    acct.bridge = std::make_unique<voip::RingRtcSipBridge>(acct.handle);
    auto* call = new IncomingSipCall(*this, iprm.callId, *acct.bridge, acct);
    acct.incomingSipCall = call;

    // Ringing, not answered yet - held here until the outgoing Signal
    // call this triggers actually connects (see onCallState's own
    // CONNECTED handler for where the real answer(200) happens).
    pj::CallOpParam ringPrm;
    ringPrm.statusCode = PJSIP_SC_RINGING;
    try {
        call->answer(ringPrm);
    } catch (pj::Error& err) {
        std::cerr << "[daemon][" << acct.config.name << "][sip] answer(180) failed: " << err.info() << "\n";
    }

    // outgoing_call_target's own e164-resolution path (ContactResolver.h)
    // reused verbatim - same CDSI-backed cache, same TTL.
    std::string resolvedTarget;
    try {
        resolvedTarget = resolveOutgoingTarget(*acct.socket, *acct.storage, destUser, g_global.resolvedContactTtlSec);
    } catch (const std::exception& e) {
        std::cerr << "[daemon][" << acct.config.name << "][sip] could not resolve '" << destUser
                   << "': " << e.what() << "\n";
    }
    if (resolvedTarget.empty()) {
        stopIncomingSipCall(acct);
        return;
    }

    acct.isCallee = false;
    uint64_t callId = signal2sip_call_start_outgoing(acct.handle, resolvedTarget.c_str(),
                                                       static_cast<uint32_t>(acct.account.device_id));
    if (callId == 0) {
        std::cerr << "[daemon][" << acct.config.name << "][sip] signal2sip_call_start_outgoing failed\n";
        stopIncomingSipCall(acct);
    }
}

// Brings up one account: Signal (storage/protocol stores/websocket/RingRTC
// call manager) always, PJSIP registration only if this account has
// [sip.<name>]. Reusable by both main()'s startup loop and reloadConfig()
// - wrapped in its own try/catch so one account's bad config/network
// failure never affects any other account sharing this process. Returns
// false (and leaves no trace in g_accounts) on failure.
bool setupAccount(const AccountConfig& accountConfig) {
    try {
        AccountState& acct = *(g_accounts[accountConfig.name] = std::make_unique<AccountState>());
        acct.config = accountConfig;

        acct.storage = std::make_unique<Storage>(g_global.dbPath, g_global.dbKey, accountConfig.name);
        if (!acct.storage->hasAccount()) {
            migrateFromNodePrototype(*acct.storage, accountConfig.e164);
        }

        acct.account = acct.storage->loadAccount();
        acct.stores = std::make_unique<ProtocolStores>(*acct.storage, "aci");
        acct.localServiceId = acct.account.aci;
        std::cout << "[daemon][" << accountConfig.name << "] own ACI: " << acct.localServiceId << "\n";

        acct.handle = signal2sip_call_manager_create(makeCallbacks(acct));
        if (!acct.handle) {
            throw std::runtime_error("could not create RingRTC call manager");
        }

        std::string username = acct.account.device_id == 1
                                    ? acct.account.aci
                                    : (acct.account.aci + "." + std::to_string(acct.account.device_id));
        acct.socket = std::make_unique<AuthSocket>(
            username, acct.account.password, "/home/vlad/GIT/vladonv/signal2sip/layer1/certs/signal-root-ca.pem",
            [&acct](const std::string& verb, const std::string& path, const Bytes& body) {
                onPush(acct, verb, path, body);
            });
        acct.sender = std::make_unique<CallMessageSender>(*acct.socket, *acct.stores, acct.account.aci,
                                                           static_cast<uint32_t>(acct.account.device_id));

        // Must be running before connect() - onPush() can start pushing
        // work onto it as soon as the socket is live.
        acct.dispatchQueue.start();

        acct.socket->connect();
        std::cout << "[daemon][" << accountConfig.name << "] connected to chat.signal.org as "
                   << acct.account.e164 << "\n";

        refreshPrekeys(*acct.storage, *acct.socket, acct.account);

        // Only a gendb-linked account (a real device linked into a real,
        // already-in-use Signal account) has a meaningful contact list to
        // sync at all - a bare gendb-registered account has no real
        // contacts, and no account_entropy_pool to derive the storage
        // service key from either. Non-fatal: a sync failure just means
        // resolveOutgoingTarget() falls back to its existing CDS-only
        // path (PNI-only for a cold e164) - see StorageServiceSync.h's own
        // doc comment for the full "why".
        if (acct.account.account_entropy_pool && !acct.account.account_entropy_pool->empty()) {
            try {
                std::vector<StorageContact> contacts =
                    fetchStorageContacts(*acct.socket, *acct.account.account_entropy_pool);
                int cachedCount = 0;
                for (const auto& contact : contacts) {
                    if (contact.e164.empty()) continue; // nothing to key resolveOutgoingTarget's cache by
                    acct.storage->saveSyncedContact(contact.e164, contact.aci, contact.pni, contact.profileKey);
                    cachedCount++;
                }
                std::cout << "[daemon][" << accountConfig.name << "] StorageService sync: " << contacts.size()
                           << " contact(s), " << cachedCount << " cached (had an e164)\n";
            } catch (const std::exception& e) {
                std::cerr << "[daemon][" << accountConfig.name << "] StorageService sync failed (non-fatal): "
                           << e.what() << "\n";
            }
        }

        if (accountConfig.hasSip()) {
            ensureSharedEndpoint(); // no-ops if g_ep already exists
            // Every account gets its own dedicated transport, bound
            // explicitly via acfg.sipConfig.transportId below - see
            // AccountConfig::sipTransport's own doc comment for why
            // sharing one transport across accounts doesn't work for
            // incoming calls.
            pj::TransportId transportId = accountConfig.sipTransport == "tls"
                                               ? createAccountTlsTransport(accountConfig)
                                               : createAccountUdpTransport(accountConfig);
            if (g_ep && transportId != PJSUA_INVALID_ID) {
                auto sipAccount = std::make_unique<BridgeAccount>();
                pj::AccountConfig acfg;
                acfg.sipConfig.transportId = transportId;
                // sips: (not sip:) is what actually routes this account's
                // registration/calls over its own TLS transport instead of
                // a UDP one - see AccountConfig::sipTransport's own doc
                // comment, including the "sip_host's port usually needs
                // updating too" gotcha.
                std::string scheme = accountConfig.sipTransport == "tls" ? "sips" : "sip";
                acfg.idUri = scheme + ":" + accountConfig.sipExtension + "@" + accountConfig.sipHost;
                acfg.regConfig.registrarUri = scheme + ":" + accountConfig.sipHost;
                pj::AuthCredInfo cred("digest", "*", accountConfig.sipExtension, 0, accountConfig.sipPassword);
                acfg.sipConfig.authCreds.push_back(cred);

                // See AccountConfig::sipSrtp's own doc comment (Config.h) -
                // "disabled" (default) leaves PJSIP's own default (plain
                // RTP) untouched.
                if (accountConfig.sipSrtp == "optional") {
                    acfg.mediaConfig.srtpUse = PJMEDIA_SRTP_OPTIONAL;
                } else if (accountConfig.sipSrtp == "mandatory") {
                    acfg.mediaConfig.srtpUse = PJMEDIA_SRTP_MANDATORY;
                }
                // srtpSecureSignaling's PJSIP default (1) REQUIRES a
                // secure/TLS transport for SRTP to negotiate at all - only
                // relax it to 0 for a plain UDP account (matches this
                // project's original SRTP verification, done over UDP);
                // a tls account leaves the default, which is now
                // genuinely satisfied instead of just working around it.
                if (accountConfig.sipSrtp != "disabled" && accountConfig.sipTransport != "tls") {
                    acfg.mediaConfig.srtpSecureSignaling = 0;
                }

                sipAccount->acctState = &acct;
                sipAccount->create(acfg);

                std::cout << "[daemon][" << accountConfig.name << "] waiting for SIP registration...\n";
                for (int i = 0; i < 100 && !sipAccount->registered.load(); i++) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                if (sipAccount->registered.load()) {
                    std::cout << "[daemon][" << accountConfig.name << "] SIP registered as "
                               << accountConfig.sipExtension << "@" << accountConfig.sipHost << "\n";
                } else {
                    std::cerr << "[daemon][" << accountConfig.name << "] SIP registration did not complete in time\n";
                }
                g_sipAccounts[accountConfig.name] = std::move(sipAccount);
            }
        }

        if (!accountConfig.outgoingCallTarget.empty()) {
            // outgoing_call_target may be a plain e164 now, not just an
            // already-known ACI/PNI - resolveOutgoingTarget leaves an
            // actual ServiceId untouched and only hits the network (real,
            // rate-limited CDSI) for an e164 that isn't already cached
            // from a previous resolution. See ContactResolver.h.
            std::string resolvedTarget;
            try {
                resolvedTarget = resolveOutgoingTarget(*acct.socket, *acct.storage, accountConfig.outgoingCallTarget,
                                                        g_global.resolvedContactTtlSec);
            } catch (const std::exception& e) {
                std::cerr << "[daemon][" << accountConfig.name << "] FAIL: could not resolve outgoing_call_target '"
                           << accountConfig.outgoingCallTarget << "': " << e.what() << "\n";
                resolvedTarget.clear();
            }
            if (!resolvedTarget.empty()) {
                std::cout << "[daemon][" << accountConfig.name << "] placing outgoing call to "
                           << accountConfig.outgoingCallTarget << " (resolved: " << resolvedTarget << ")\n";
                uint64_t callId = signal2sip_call_start_outgoing(acct.handle, resolvedTarget.c_str(),
                                                                  static_cast<uint32_t>(acct.account.device_id));
                if (callId == 0) {
                    std::cerr << "[daemon][" << accountConfig.name
                               << "] FAIL: signal2sip_call_start_outgoing failed\n";
                }
            }
        } else {
            std::cout << "[daemon][" << accountConfig.name << "] waiting for incoming calls\n";
        }
        return true;
    } catch (const std::exception& e) {
        std::cerr << "[daemon][" << accountConfig.name << "] account setup failed: " << e.what()
                   << " - skipping this account, continuing with the rest\n";
        // If the failure happened after dispatchQueue.start() (e.g.
        // socket->connect() or SIP registration throwing), its worker
        // thread is still running - erasing the map entry directly would
        // destroy a joinable std::thread and call std::terminate() instead
        // of unwinding cleanly. stopAndJoin() is always safe to call even
        // if start() was never reached (EnvelopeDispatchQueue::stopAndJoin()
        // no-ops on a non-joinable thread).
        if (auto it = g_accounts.find(accountConfig.name); it != g_accounts.end()) {
            it->second->dispatchQueue.stopAndJoin();
            // Same reasoning: if signal2sip_call_manager_create() already
            // succeeded before the failure, its handle would otherwise
            // leak (own threads, WebRTC PeerConnectionFactory, raw-PCM
            // ADM) since it never reaches the normal shutdown path below.
            if (it->second->handle) {
                signal2sip_call_manager_destroy(it->second->handle);
            }
            if (it->second->socket) {
                it->second->socket->close();
            }
        }
        g_accounts.erase(accountConfig.name);
        return false;
    }
}

// Tears down one account: stop any active SIP bridge, drain and join its
// dispatch queue (queued work dereferences acct.handle/stores/socket, so
// this must happen before any of those are destroyed), then tear down
// RingRTC and the websocket. Reusable by both final shutdown and
// reloadConfig(). No-ops if `name` isn't currently running.
void teardownAccount(const std::string& name) {
    auto it = g_accounts.find(name);
    if (it == g_accounts.end()) return;
    AccountState& acct = *it->second;
    stopSipBridge(acct);
    stopIncomingSipCall(acct);
    acct.dispatchQueue.stopAndJoin();
    signal2sip_call_manager_destroy(acct.handle);
    acct.socket->close();
    g_sipAccounts.erase(name);
    g_accounts.erase(it);
}

// SIGHUP handler's actual work, run from the main loop (never from the
// signal handler itself). Diffs the freshly-reread config against
// g_accounts: accounts no longer present get torn down, accounts not yet
// present get set up. Accounts present in both are left running untouched
// - changing an existing account's settings (e.g. a new SIP password) is
// not supported by a reload; that would need this account removed from
// the config, reloaded, then re-added in a second reload.
void reloadConfig(const std::string& configPath) {
    DaemonConfig newConfig;
    try {
        newConfig = DaemonConfig::load(configPath);
    } catch (const std::exception& e) {
        std::cerr << "[daemon] reload: config error: " << e.what() << " - keeping the previous config running\n";
        return;
    }

    // Accounts already running were constructed against the *old* g_global
    // (captured by value at construction time inside their own Storage),
    // so updating this doesn't retroactively change them - only new
    // accounts brought up below see the new value. Consistent with
    // "changing settings isn't supported by a reload" above.
    g_global = newConfig.global;

    std::set<std::string> newNames;
    for (const auto& accountConfig : newConfig.accounts) newNames.insert(accountConfig.name);

    for (auto it = g_accounts.begin(); it != g_accounts.end(); ) {
        if (!newNames.count(it->first)) {
            std::cout << "[daemon] reload: removing account " << it->first << "\n";
            std::string name = it->first;
            ++it; // teardownAccount() erases g_accounts[name] itself
            teardownAccount(name);
        } else {
            ++it;
        }
    }

    for (const auto& accountConfig : newConfig.accounts) {
        if (!g_accounts.count(accountConfig.name)) {
            std::cout << "[daemon] reload: adding account " << accountConfig.name << "\n";
            setupAccount(accountConfig);
        }
    }
}

void printUsage() {
    std::cerr
        << "usage: signal2sip-daemon [config-path]\n"
          "\n"
          "Config file defaults to /etc/signal2sip/signal2sip.conf (else ./signal2sip.conf) when no\n"
          "path is given - see signal2sip-gendb --help to create one. Send SIGHUP to reload\n"
          "[account.<name>] additions/removals without restarting; existing accounts' own settings are\n"
          "not re-read on a reload, see reloadConfig()'s doc comment above.\n";
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
    }

    // A redirected (non-tty) stdout is fully buffered by default - a
    // long-running daemon's log output would otherwise sit invisible in
    // an in-process buffer for a long time (or vanish entirely on a
    // crash). Confirmed live: the test harnesses this project already
    // has hit the exact same issue (see pjsip_ringrtc_echo_test.cpp's
    // comment on the same fix).
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    // Required once per process before any RegistrationClient use (see
    // that class's own doc comment) - StorageServiceSync's storage.signal.org
    // calls are the first daemon-side (not just gendb-side) user of it.
    curl_global_init(CURL_GLOBAL_DEFAULT);

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);
    // Reload config (add/remove accounts) without restarting - see
    // reloadConfig()'s own doc comment above for exactly what it does and
    // does not support.
    std::signal(SIGHUP, onReloadSignal);

    g_configPath = resolveConfigPath(argc, argv);
    DaemonConfig config;
    try {
        config = DaemonConfig::load(g_configPath);
    } catch (const std::exception& e) {
        std::cerr << "[daemon] config error: " << e.what() << "\n";
        return 1;
    }
    std::cout << "[daemon] loaded config from " << g_configPath << " for " << config.accounts.size()
               << " account(s)\n";
    g_global = config.global;

    signal2sip_init_logging(); // process-wide, once, regardless of account count

    // --- Shared PJSIP Endpoint, once, only if at least one account uses
    // [sip.<name>] - see g_ep's own doc comment for why this is the one
    // thing that stays a process-wide singleton instead of per-account.
    // setNullDev() matches pjsip_ringrtc_echo_test.cpp's proven config;
    // ptime/clockRate/forced-L16-mono-codec matches tg2sip-webrtc's
    // sip.cpp (settings.raw_pcm()) exactly - same rationale:
    // RingRtcSipBridge's ring-buffer ports are fixed 48kHz mono, so
    // negotiating raw L16/48000/1 directly (instead of letting
    // PJSIP/Asterisk pick from the full default codec list - narrowband
    // PCMU needed a real resample_port conversion, and even wideband
    // Opus is lossy-compressed and offered as stereo/2ch, a
    // channel-count mismatch against these mono ports) removes every
    // remaining source of rate/channel mismatch and codec-level
    // encode/decode CPU overhead in the whole audio path. Found live:
    // real degraded audio quality (described as sounding slowed-down)
    // over PCMU with the resample_port conversion in place.
    bool anySip = std::any_of(config.accounts.begin(), config.accounts.end(),
                               [](const AccountConfig& a) { return a.hasSip(); });
    if (anySip) {
        // Just brings up the shared pjsua2 Endpoint itself - each
        // account's own dedicated transport is created later in the
        // per-account loop below (see g_ep's own doc comment).
        ensureSharedEndpoint();
    }

    // --- Per-account setup (see setupAccount()'s own doc comment).
    for (const AccountConfig& accountConfig : config.accounts) {
        setupAccount(accountConfig);
    }

    if (g_accounts.empty()) {
        std::cerr << "[daemon] no account came up successfully, exiting\n";
        return 1;
    }

    while (g_running.load()) {
        if (g_reloadRequested.exchange(false)) {
            std::cout << "[daemon] SIGHUP received, reloading config from " << g_configPath << "\n";
            reloadConfig(g_configPath);
        }

        // Registration watchdog - see BridgeAccount::unregisteredSinceMs's
        // own doc comment for why this exists (PJSIP silently gives up
        // forever on failure codes like 403, outside its own small
        // auto-retry allowlist). setRegistration(true) just sends a fresh
        // REGISTER through the same account/transport - it's the same
        // call PJSIP's own auto-retry would have made, so this is a
        // no-op on the (common) case where the account is fine or PJSIP
        // is already handling the retry itself; it only matters for the
        // stuck case.
        int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now().time_since_epoch())
                            .count();
        for (auto& [name, sipAccount] : g_sipAccounts) {
            int64_t since = sipAccount->unregisteredSinceMs.load();
            if (since != 0 && nowMs - since >= static_cast<int64_t>(g_global.sipRegWatchdogSec) * 1000) {
                std::cerr << "[daemon][" << name << "] registration watchdog: still unregistered after "
                           << g_global.sipRegWatchdogSec << "s, forcing a fresh attempt\n";
                try {
                    sipAccount->setRegistration(true);
                } catch (pj::Error& err) {
                    std::cerr << "[daemon][" << name << "] watchdog re-registration attempt failed: " << err.info()
                               << "\n";
                }
                // Reset the clock regardless of outcome - if it's still
                // down next tick, we'll try again after another full
                // watchdog interval rather than spamming every 200ms.
                sipAccount->unregisteredSinceMs = nowMs;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Shutdown, per account (see teardownAccount()'s own doc comment).
    // unique_ptr members (storage/stores/socket/sender) clean themselves
    // up once each AccountState itself is erased.
    while (!g_accounts.empty()) {
        teardownAccount(g_accounts.begin()->first);
    }
    return 0;
}
