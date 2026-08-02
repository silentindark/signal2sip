// Milestone G: signal2sip-daemon - combines A-F into one process per
// account (see /home/vlad/.claude/plans/jiggly-mapping-plum.md). No IPC,
// no Node - real Signal Protocol send/receive (Milestone B), RingRTC
// calling (D/E), and the PJSIP ring-buffer bridge (F), all driven by
// real incoming/outgoing Signal calls instead of a synthetic in-process
// test.
//
// Two roles a running instance can take, inferred from config (not an
// explicit mode flag - matches how the two accounts in this milestone's
// live verification are actually configured):
//   - Incoming Signal call + [sip] bridge_destination configured: answers
//     automatically and bridges the call's audio to a real SIP call via
//     RingRtcSipBridge (native/voip/), same pattern
//     pjsip_ringrtc_echo_test.cpp's peerB proved live against DPDZK's *43.
//   - [other] outgoing_call_target configured: places an outgoing Signal
//     call and pushes/pulls raw audio directly (no SIP leg) - this
//     instance is the "test probe" side of the live verification,
//     measuring RMS to confirm the round trip through the other
//     instance's SIP bridge actually carried real audio. Mirrors
//     pjsip_ringrtc_echo_test.cpp's peerA.

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

#include <nlohmann/json.hpp>
#include <pjmedia/resample.h>
#include <pjsua-lib/pjsua.h>
#include <pjsua2.hpp>

#include "CallSignaling.h"
#include "Config.h"
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
// (+123456789004, +123456789002) - imports the Node prototype's JSON
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
// when main() destroyed the objects (g_state.stores/socket/handle) it
// dereferences, a genuine use-after-free on shutdown. A single worker
// thread with a FIFO queue fixes all three: one thread total, strict
// arrival order, and something concrete for shutdown to join.
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

// Everything the C-ABI callbacks (plain function pointers, no captures)
// need access to via their void* context.
struct DaemonState {
    Config config;
    Storage* storage;
    ProtocolStores* stores;
    AccountRecord account;
    std::string localServiceId; // == account.aci
    AuthSocket* socket;
    CallMessageSender* sender;
    Signal2sipCallManagerHandle* handle;

    // Set once a call is active - the far end's serviceId, used because
    // RingRTC's callbacks give us remote_peer_id already, but call_state
    // doesn't, and we need it to know who to bridge/probe against.
    std::atomic<uint64_t> activeCallId{0};
    std::atomic<bool> isCallee{false};
    std::string remotePeerId;

    // Only ever one of these is non-null at a time (this project's
    // one-call-at-a-time scope, matching RingRTC's own single-active-call
    // design).
    std::unique_ptr<voip::RingRtcSipBridge> bridge;
    pj::Call* sipCall = nullptr;

    pj::Endpoint* ep = nullptr;
};

DaemonState g_state;
EnvelopeDispatchQueue g_dispatchQueue;

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

void onSendOffer(void*, const char* remotePeerId, uint64_t callId, int32_t mediaType, const uint8_t* opaque,
                   size_t opaqueLen) {
    std::cout << "[daemon] send_offer -> " << remotePeerId << "\n";
    safeCallback("send_offer", [&] {
        g_state.sender->sendOffer(remotePeerId, callId, mediaType, opaque, opaqueLen);
        signal2sip_call_message_sent(g_state.handle, callId);
    });
}

void onSendAnswer(void*, const char* remotePeerId, uint64_t callId, const uint8_t* opaque, size_t opaqueLen) {
    std::cout << "[daemon] send_answer -> " << remotePeerId << "\n";
    safeCallback("send_answer", [&] {
        g_state.sender->sendAnswer(remotePeerId, callId, opaque, opaqueLen);
        signal2sip_call_message_sent(g_state.handle, callId);
    });
}

void onSendIce(void*, const char* remotePeerId, uint64_t callId, bool hasReceiverDeviceId, uint32_t receiverDeviceId,
                const uint8_t* opaque, size_t opaqueLen) {
    safeCallback("send_ice", [&] {
        g_state.sender->sendIce(remotePeerId, callId, hasReceiverDeviceId, receiverDeviceId, opaque, opaqueLen);
        signal2sip_call_message_sent(g_state.handle, callId);
    });
}

void onSendHangup(void*, const char* remotePeerId, uint64_t callId, int32_t hangupType, uint32_t hangupDeviceId) {
    std::cout << "[daemon] send_hangup -> " << remotePeerId << "\n";
    safeCallback("send_hangup", [&] {
        g_state.sender->sendHangup(remotePeerId, callId, hangupType, hangupDeviceId);
        signal2sip_call_message_sent(g_state.handle, callId);
    });
}

// --- SIP bridging (mirrors pjsip_ringrtc_echo_test.cpp's BridgeCall) ---

class BridgeCall : public pj::Call {
public:
    BridgeCall(pj::Account& acc, voip::RingRtcSipBridge& bridge) : pj::Call(acc), bridge_(bridge) {}

    void onCallState(pj::OnCallStateParam&) override {
        pj::CallInfo ci = getInfo();
        std::cout << "[daemon][sip] call state=" << ci.stateText << " (" << ci.state << ")\n";
        if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
            disconnected_ = true;
        }
    }

    void onCallMediaState(pj::OnCallMediaStateParam&) override {
        pj::CallInfo ci = getInfo();
        for (unsigned i = 0; i < ci.media.size(); i++) {
            if (ci.media[i].type != PJMEDIA_TYPE_AUDIO || !getMedia(i)) continue;
            auto* aud = static_cast<pj::AudioMedia*>(getMedia(i));
            unsigned callRate = aud->getPortInfo().format.clockRate;
            std::cout << "[daemon][sip] call clock rate: " << callRate << "\n";

            // Non-resampling PJSIP conference bridge in this build - see
            // pjsip_ringrtc_echo_test.cpp's onCallMediaState for the full
            // story (real 488 Not Acceptable Here forcing 48kHz against
            // DPDZK's *43, this resample-port approach is the fix that
            // works for any call regardless of negotiated codec).
            pj_pool_t* pool = pjsua_pool_create("resample", 2048, 512);
            pjmedia_port* inResample = nullptr;
            pjmedia_resample_port_create(pool, bridge_.InputPjmediaPort(), callRate, 0, &inResample);
            pjsua_conf_port_id inResampleId = PJSUA_INVALID_ID;
            pjsua_conf_add_port(pool, inResample, &inResampleId);
            pjsua_conf_connect(aud->getPortId(), inResampleId);

            pjmedia_port* outResample = nullptr;
            pjmedia_resample_port_create(pool, bridge_.OutputPjmediaPort(), callRate, 0, &outResample);
            pjsua_conf_port_id outResampleId = PJSUA_INVALID_ID;
            pjsua_conf_add_port(pool, outResample, &outResampleId);
            pjsua_conf_connect(outResampleId, aud->getPortId());

            std::cout << "[daemon][sip] audio wired to RingRtcSipBridge via resample ports\n";
            bridge_.Start();
        }
    }

    std::atomic<bool> disconnected_{false};

private:
    voip::RingRtcSipBridge& bridge_;
};

class BridgeAccount : public pj::Account {
public:
    std::atomic<bool> registered{false};
    void onRegState(pj::OnRegStateParam&) override {
        pj::AccountInfo ai = getInfo();
        std::cout << "[daemon][sip] reg state active=" << ai.regIsActive << "\n";
        if (ai.regIsActive) registered = true;
    }
};

BridgeAccount* g_sipAccount = nullptr;

// Starts bridging the currently-active RingRTC call to a real SIP call
// dialing config.sipBridgeDestination - called once the Signal call is
// Accepted (real audio about to flow both ways).
void startSipBridge() {
    if (!g_sipAccount || !g_sipAccount->registered) {
        std::cerr << "[daemon] cannot bridge to SIP: not registered\n";
        return;
    }

    // PJSUA2 requires every thread that calls into it to be registered
    // with PJLIB first (Endpoint::libRegisterThread()), unless it's the
    // thread that originally initialized the library (main()'s thread,
    // which called ep.libCreate()/libInit()/libStart()) or one of
    // PJSIP's own worker threads. onCallState() (and therefore this
    // function) runs on whatever thread RingRTC invokes its call_state
    // callback from - not main()'s thread - so register it here, once
    // per OS thread. Found live: without this, makeCall() below still
    // sent a real INVITE (the transport layer tolerated the unregistered
    // thread fine), but PJSIP's automatic 401-challenge auto-retry -
    // which relies on the dialog's thread-local auth session state -
    // never fired, so a real call to DPDZK's *43 got exactly one INVITE,
    // one 401, and then silently never connected.
    thread_local bool sipThreadRegistered = false;
    if (!sipThreadRegistered && g_state.ep) {
        try {
            g_state.ep->libRegisterThread("ringrtc-callback");
        } catch (pj::Error& err) {
            std::cerr << "[daemon] libRegisterThread failed: " << err.info() << "\n";
        }
        sipThreadRegistered = true;
    }

    g_state.bridge = std::make_unique<voip::RingRtcSipBridge>(g_state.handle);

    std::string destUri = "sip:" + g_state.config.sipBridgeDestination + "@" + g_state.config.sipHost;
    std::cout << "[daemon][sip] placing bridge call to " << destUri << "\n";
    auto* call = new BridgeCall(*g_sipAccount, *g_state.bridge);
    g_state.sipCall = call;
    pj::CallOpParam prm(true);
    prm.opt.audioCount = 1;
    prm.opt.videoCount = 0;
    try {
        call->makeCall(destUri, prm);
    } catch (pj::Error& err) {
        std::cerr << "[daemon] FAIL: makeCall: " << err.info() << "\n";
    }
}

void stopSipBridge() {
    if (g_state.bridge) {
        g_state.bridge->Stop();
    }
    if (g_state.sipCall) {
        auto* call = static_cast<BridgeCall*>(g_state.sipCall);
        pj::CallOpParam hprm;
        try {
            call->hangup(hprm);
        } catch (...) {
        }
        for (int i = 0; i < 50 && !call->disconnected_.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        delete call;
        g_state.sipCall = nullptr;
    }
    g_state.bridge.reset();
}

// --- Outgoing-call test probe (mirrors pjsip_ringrtc_echo_test.cpp's peerA) ---

std::atomic<bool> g_probeRunning{false};
std::atomic<bool> g_probeCompleted{false};

void runProbe() {
    g_probeRunning = true;
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
        signal2sip_push_recorded_samples(g_state.handle, tone.data() + offset, n);
        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(g_state.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "[daemon][probe] pulled " << received.size() << " samples\n";
    double sumSquares = 0;
    for (int16_t s : received) sumSquares += static_cast<double>(s) * s;
    double rms = received.empty() ? 0.0 : std::sqrt(sumSquares / received.size());
    std::cout << "[daemon][probe] RMS of received (echoed) audio: " << rms << "\n";
    bool audioFlowed = received.size() > static_cast<size_t>(sampleRate) && rms > 20.0;
    std::cout << (audioFlowed ? "PASS" : "FAIL") << ": tone round-tripped through the real Signal call + remote's SIP bridge\n";

    signal2sip_call_hangup(g_state.handle);
    g_probeRunning = false;
    g_probeCompleted = true;
}

// --- RingRTC call state machine ---

void onCallState(void*, const char* remotePeerId, uint64_t callId, int32_t state) {
    g_state.activeCallId = callId;
    g_state.remotePeerId = remotePeerId;
    std::cout << "[daemon] call_state -> " << state << " (peer " << remotePeerId << ")\n";

    // Called synchronously from RingRTC (Rust) - same FFI-exception-safety
    // reasoning as the onSend* callbacks above.
    safeCallback("onCallState", [&] {
        if (state == SIGNAL2SIP_CALL_STATE_OUTGOING_AUDIO) {
            signal2sip_call_proceed(g_state.handle, callId);
        } else if (state == SIGNAL2SIP_CALL_STATE_INCOMING_AUDIO) {
            g_state.isCallee = true;
            signal2sip_call_proceed(g_state.handle, callId);
        } else if (state == SIGNAL2SIP_CALL_STATE_RINGING && g_state.isCallee.load()) {
            // See signal2sip_call_accept()'s doc comment - must wait for
            // Ringing, not accept right after proceed().
            signal2sip_call_accept(g_state.handle, callId);
        } else if (state == SIGNAL2SIP_CALL_STATE_CONNECTED) {
            if (g_state.isCallee.load() && !g_state.config.sipBridgeDestination.empty()) {
                startSipBridge();
            } else if (!g_state.isCallee.load() && !g_state.config.outgoingCallTarget.empty()) {
                std::thread(runProbe).detach();
            }
        } else if (state == SIGNAL2SIP_CALL_STATE_ENDED || state == SIGNAL2SIP_CALL_STATE_CONCLUDED) {
            stopSipBridge();
            g_state.isCallee = false;
        }
    });
}

Signal2sipCallbacks makeCallbacks() {
    Signal2sipCallbacks cb{};
    cb.send_offer = onSendOffer;
    cb.send_answer = onSendAnswer;
    cb.send_ice = onSendIce;
    cb.send_hangup = onSendHangup;
    cb.call_state = onCallState;
    return cb;
}

// --- Incoming envelope handling ---

void onPush(const std::string& verb, const std::string& path, const Bytes& body) {
    if (verb != "PUT" || path != "/api/v1/message" || body.empty()) return;

    signalservice::Envelope envelope;
    if (!envelope.ParseFromArray(body.data(), static_cast<int>(body.size()))) {
        std::cerr << "[daemon] failed to parse pushed Envelope\n";
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
        std::lock_guard<std::mutex> lock(g_state.stores->mutex());
        if (envelope.type() == signalservice::Envelope_Type_UNIDENTIFIED_SENDER) {
            Bytes ciphertext(envelope.content().begin(), envelope.content().end());
            SealedSenderResult result =
                decryptSealedSender(*g_state.stores, Address{g_state.localServiceId, static_cast<uint32_t>(g_state.account.device_id)},
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
            plaintext = decryptCiphertext(*g_state.stores,
                                          Address{g_state.localServiceId, static_cast<uint32_t>(g_state.account.device_id)},
                                          Address{senderServiceId, senderDeviceId}, originalMessageType,
                                          originalCiphertext);
        } else {
            return; // receipt/other envelope type - nothing to decrypt
        }
    } catch (const std::exception& e) {
        std::cerr << "[daemon] failed to decrypt envelope: " << e.what() << "\n";
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
            g_dispatchQueue.push([senderServiceId, senderDeviceId, originalCiphertext, originalMessageType,
                                  clientTimestamp = envelope.clienttimestamp()] {
                sendDecryptionErrorReply(*g_state.socket, *g_state.stores, *g_state.sender, g_state.localServiceId,
                                         static_cast<uint32_t>(g_state.account.device_id), senderServiceId,
                                         senderDeviceId, originalCiphertext, originalMessageType, clientTimestamp);
            });
        }
        return;
    }

    std::cout << "[daemon][diag] decrypted envelope from " << senderServiceId << " device " << senderDeviceId
               << " (" << plaintext.size() << " bytes plaintext)\n";

    signalservice::Content content;
    if (!content.ParseFromArray(plaintext.data(), static_cast<int>(plaintext.size()))) {
        std::cerr << "[daemon] failed to parse decrypted Content\n";
        return;
    }
    if (content.has_datamessage()) {
        std::cout << "[daemon][diag] DataMessage body: " << content.datamessage().body() << "\n";
    }
    if (!content.has_callmessage()) return;

    std::cout << "[daemon] CallMessage from " << senderServiceId << " device " << senderDeviceId << "\n";

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
    uint32_t localDeviceId = static_cast<uint32_t>(g_state.account.device_id);
    g_dispatchQueue.push([senderServiceId, senderDeviceId, localDeviceId, callMessage] {
        handleCallMessage(g_state.handle, *g_state.stores, senderServiceId, senderDeviceId, localDeviceId,
                          callMessage);
    });
}

std::atomic<bool> g_running{true};
void onSignal(int) { g_running = false; }

} // namespace

int main(int argc, char** argv) {
    // A redirected (non-tty) stdout is fully buffered by default - a
    // long-running daemon's log output would otherwise sit invisible in
    // an in-process buffer for a long time (or vanish entirely on a
    // crash). Confirmed live: the test harnesses this project already
    // has hit the exact same issue (see pjsip_ringrtc_echo_test.cpp's
    // comment on the same fix).
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    std::string configPath = resolveConfigPath(argc, argv);
    Config config;
    try {
        config = Config::load(configPath);
    } catch (const std::exception& e) {
        std::cerr << "[daemon] config error: " << e.what() << "\n";
        return 1;
    }
    std::cout << "[daemon] loaded config from " << configPath << " for " << config.e164 << "\n";

    std::string dbPath = config.accountDataDir + "/" + config.e164 + ".db";
    Storage storage(dbPath, config.dbKey);
    if (!storage.hasAccount()) {
        try {
            migrateFromNodePrototype(storage, config.e164);
        } catch (const std::exception& e) {
            std::cerr << "[daemon] no account in storage and migration failed: " << e.what() << "\n";
            return 1;
        }
    }

    AccountRecord account = storage.loadAccount();
    ProtocolStores stores(storage, "aci");

    g_state.config = config;
    g_state.storage = &storage;
    g_state.stores = &stores;
    g_state.account = account;
    g_state.localServiceId = account.aci;

    signal2sip_init_logging();
    g_state.handle = signal2sip_call_manager_create(makeCallbacks());
    if (!g_state.handle) {
        std::cerr << "[daemon] FAIL: could not create RingRTC call manager\n";
        return 1;
    }

    std::string username = account.device_id == 1 ? account.aci : (account.aci + "." + std::to_string(account.device_id));
    AuthSocket socket(username, account.password, "/home/vlad/GIT/vladonv/signal2sip/layer1/certs/signal-root-ca.pem",
                      onPush);
    g_state.socket = &socket;
    CallMessageSender sender(socket, stores, account.aci, static_cast<uint32_t>(account.device_id));
    g_state.sender = &sender;

    // Must be running before connect() - onPush() can start pushing work
    // onto it as soon as the socket is live.
    g_dispatchQueue.start();

    socket.connect();
    std::cout << "[daemon] connected to chat.signal.org as " << account.e164 << "\n";

    refreshPrekeys(storage, socket, account);

    // --- PJSIP setup, once at startup - registers immediately so a
    // bridge call can be placed the moment an incoming Signal call needs
    // one. setNullDev() matches pjsip_ringrtc_echo_test.cpp's proven
    // config; ptime/clockRate/forced-L16-mono-codec matches
    // tg2sip-webrtc's sip.cpp (settings.raw_pcm()) exactly - same
    // rationale: RingRtcSipBridge's ring-buffer ports are fixed
    // 48kHz mono, so negotiating raw L16/48000/1 directly (instead of
    // letting PJSIP/Asterisk pick from the full default codec list -
    // narrowband PCMU needed a real resample_port conversion, and even
    // wideband Opus is lossy-compressed and offered as stereo/2ch,
    // a channel-count mismatch against these mono ports) removes every
    // remaining source of rate/channel mismatch and codec-level
    // encode/decode CPU overhead in the whole audio path. Found live:
    // real degraded audio quality (described as sounding slowed-down)
    // over PCMU with the resample_port conversion in place.
    pj::Endpoint ep;
    BridgeAccount sipAccount;
    if (!config.sipHost.empty()) {
        try {
            ep.libCreate();
            pj::EpConfig epConfig;
            epConfig.medConfig.ecTailLen = 0;
            epConfig.medConfig.noVad = true;
            // 10ms ptime required to keep an uncompressed L16 RTP packet
            // below the MTU (tg2sip-webrtc/tg2sip/sip.cpp's own comment).
            epConfig.medConfig.audioFramePtime = 10;
            epConfig.medConfig.ptime = 10;
            epConfig.medConfig.clockRate = 48000;
            ep.libInit(epConfig);
            ep.audDevManager().setNullDev();

            // Force L16/48000/1 (raw PCM, mono) as the only codec PJSIP
            // will ever offer/accept, matching RingRtcSipBridge's fixed
            // format exactly - same technique as tg2sip-webrtc's
            // ep.codecSetPriority() loop.
            for (const auto* codec : ep.codecEnum()) {
                ep.codecSetPriority(codec->codecId, codec->codecId == "L16/48000/1" ? 255 : 0);
            }

            pj::TransportConfig tcfg;
            tcfg.port = config.sipPort;
            ep.transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
            ep.libStart();

            pj::AccountConfig acfg;
            acfg.idUri = "sip:" + config.sipExtension + "@" + config.sipHost;
            acfg.regConfig.registrarUri = "sip:" + config.sipHost;
            pj::AuthCredInfo cred("digest", "*", config.sipExtension, 0, config.sipPassword);
            acfg.sipConfig.authCreds.push_back(cred);
            sipAccount.create(acfg);
            g_sipAccount = &sipAccount;
            g_state.ep = &ep;

            std::cout << "[daemon] waiting for SIP registration...\n";
            for (int i = 0; i < 100 && !sipAccount.registered.load(); i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (sipAccount.registered.load()) {
                std::cout << "[daemon] SIP registered as " << config.sipExtension << "@" << config.sipHost << "\n";
            } else {
                std::cerr << "[daemon] SIP registration did not complete in time\n";
            }
        } catch (pj::Error& err) {
            std::cerr << "[daemon] SIP setup failed: " << err.info() << "\n";
        }
    }

    if (!config.outgoingCallTarget.empty()) {
        std::cout << "[daemon] placing outgoing call to " << config.outgoingCallTarget << "\n";
        uint64_t callId = signal2sip_call_start_outgoing(g_state.handle, config.outgoingCallTarget.c_str(),
                                                          static_cast<uint32_t>(account.device_id));
        if (callId == 0) {
            std::cerr << "[daemon] FAIL: signal2sip_call_start_outgoing failed\n";
        }
    } else {
        std::cout << "[daemon] waiting for incoming calls\n";
    }

    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!g_state.config.outgoingCallTarget.empty() && g_probeCompleted.load()) {
            // This instance's only job was the outgoing test-probe call,
            // and runProbe() already measured its result and hung up.
            break;
        }
    }

    stopSipBridge();

    // Must happen before anything below: queued work (handleCallMessage/
    // sendDecryptionErrorReply) dereferences g_state.handle/stores/socket,
    // and those are about to be destroyed. stopAndJoin() blocks until the
    // worker thread finishes whatever it's currently running (bounded by
    // AuthSocket::request()'s own ~30s timeout in the worst case, if a
    // network call is in flight) - a bounded shutdown delay is a fine
    // trade for not risking a use-after-free.
    g_dispatchQueue.stopAndJoin();

    signal2sip_call_manager_destroy(g_state.handle);
    socket.close();
    return 0;
}
