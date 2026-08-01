// Milestone F live verification (see /home/vlad/.claude/plans/
// jiggly-mapping-plum.md): proves RingRtcSipBridge (native/voip/
// ringrtc_sip_bridge.h) actually carries real audio between a RingRTC
// call and a real SIP call, with no OS audio device anywhere in the
// path - the same discipline as ringrtc_two_party_test.cpp, extended
// with a real SIP leg to FreePBX's built-in echo test (*43).
//
// Two processes (same fork()+AF_UNIX-SOCK_SEQPACKET pattern as
// ringrtc_two_party_test.cpp, and for the same reason: ringrtc's own
// rffi audio_device.cc keeps its registered AudioTransport* in a single
// process-wide global, so two CallManagers must not share a process -
// see this project's memory project_signal2sip_milestone_e_progress):
//
//   peerA (this process's parent): plain RingRTC peer, exactly like
//   ringrtc_two_party_test.cpp's peerA - pushes a 440Hz tone into its own
//   "microphone", then pulls its own playout and measures RMS. If the
//   round trip through peerB's SIP leg and DPDZK's echo test worked,
//   peerA should hear its own tone (delayed by FreePBX's greeting +
//   the echo) coming back.
//
//   peerB (the forked child): a RingRTC callee bridged via
//   RingRtcSipBridge to a real PJSIP call to DPDZK's *43 echo test
//   (spike4/pjsip-echo-test.cpp's proven Account/Call/onCallMediaState
//   pattern, minus the real sound device - audio flows through
//   RingRtcSipBridge's ring buffers instead of
//   audDevManager().getCaptureDevMedia()/getPlaybackDevMedia()).
//
// Usage: pjsip_ringrtc_echo_test <sip_host> <extension> <password>
// (same argv shape as spike4/pjsip-echo-test.cpp and
// gateway/pjsip-gateway.cpp - dials "*43" on that host).

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include <pjmedia/resample.h>
#include <pjsua-lib/pjsua.h>
#include <pjsua2.hpp>

#include "../ringrtc/signal2sip_ringrtc.h"
#include "../voip/ringrtc_sip_bridge.h"

namespace {

enum class MsgType : uint8_t { Offer = 0, Answer = 1, Ice = 2, Ready = 3 };

constexpr size_t kMaxMsg = 4096;
constexpr size_t kHeaderLen = 1 + sizeof(uint64_t);

struct LocalPeer {
    const char* name = nullptr;
    const char* otherName = nullptr;
    int sockFd = -1;
    Signal2sipCallManagerHandle* handle = nullptr;
    std::atomic<uint64_t> callId{0};
    std::atomic<int32_t> lastState{-1};
    std::atomic<bool> isCallee{false};
    std::atomic<bool> otherReady{false};
};

void sendMessage(LocalPeer& self, MsgType type, uint64_t callId, const uint8_t* payload, size_t payloadLen) {
    std::vector<uint8_t> buf(kHeaderLen + payloadLen);
    buf[0] = static_cast<uint8_t>(type);
    std::memcpy(buf.data() + 1, &callId, sizeof(callId));
    if (payloadLen > 0) std::memcpy(buf.data() + kHeaderLen, payload, payloadLen);
    ssize_t n = send(self.sockFd, buf.data(), buf.size(), 0);
    if (n < 0 || static_cast<size_t>(n) != buf.size()) {
        std::cerr << "[" << self.name << "] send() failed: " << strerror(errno) << "\n";
    }
}

void onSendOffer(void* ctx, const char*, uint64_t callId, int32_t, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    self->callId = callId;
    std::cout << "[" << self->name << "] send_offer (len=" << opaqueLen << ") -> " << self->otherName << "\n";
    sendMessage(*self, MsgType::Offer, callId, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendAnswer(void* ctx, const char*, uint64_t callId, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    std::cout << "[" << self->name << "] send_answer (len=" << opaqueLen << ") -> " << self->otherName << "\n";
    sendMessage(*self, MsgType::Answer, callId, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendIce(void* ctx, const char*, uint64_t callId, bool, uint32_t, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    sendMessage(*self, MsgType::Ice, callId, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendHangup(void* ctx, const char*, uint64_t callId, int32_t, uint32_t) {
    auto* self = static_cast<LocalPeer*>(ctx);
    std::cout << "[" << self->name << "] send_hangup\n";
    signal2sip_call_message_sent(self->handle, callId);
}

void onCallState(void* ctx, const char*, uint64_t callId, int32_t state) {
    auto* self = static_cast<LocalPeer*>(ctx);
    self->callId = callId;
    self->lastState = state;
    std::cout << "[" << self->name << "] call_state -> " << state << "\n";
    if (state == SIGNAL2SIP_CALL_STATE_OUTGOING_AUDIO) {
        signal2sip_call_proceed(self->handle, callId);
    } else if (state == SIGNAL2SIP_CALL_STATE_INCOMING_AUDIO) {
        self->isCallee = true;
        signal2sip_call_proceed(self->handle, callId);
    } else if (state == SIGNAL2SIP_CALL_STATE_RINGING && self->isCallee.load()) {
        signal2sip_call_accept(self->handle, callId);
    }
}

Signal2sipCallbacks makeCallbacks(LocalPeer& peer) {
    Signal2sipCallbacks cb{};
    cb.context = &peer;
    cb.send_offer = onSendOffer;
    cb.send_answer = onSendAnswer;
    cb.send_ice = onSendIce;
    cb.send_hangup = onSendHangup;
    cb.call_state = onCallState;
    return cb;
}

bool waitForState(LocalPeer& peer, int32_t state, int timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (peer.lastState.load() == state) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

bool waitForOtherReady(LocalPeer& peer, int timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (peer.otherReady.load()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

void signalingReaderLoop(LocalPeer& self) {
    std::vector<uint8_t> buf(kMaxMsg);
    for (;;) {
        ssize_t n = recv(self.sockFd, buf.data(), buf.size(), 0);
        if (n <= 0) return;
        if (static_cast<size_t>(n) < kHeaderLen) continue;

        auto type = static_cast<MsgType>(buf[0]);
        uint64_t callId;
        std::memcpy(&callId, buf.data() + 1, sizeof(callId));
        const uint8_t* payload = buf.data() + kHeaderLen;
        size_t payloadLen = static_cast<size_t>(n) - kHeaderLen;

        switch (type) {
            case MsgType::Offer: {
                // Synthetic same-process test - see ringrtc_two_party_test.cpp's
                // identical comment (all-zero keys work symmetrically here).
                uint8_t zeroKey[32] = {0};
                signal2sip_call_received_offer(self.handle, self.otherName, callId, 1, 1, payload, payloadLen,
                                                zeroKey, zeroKey);
                break;
            }
            case MsgType::Answer: {
                // Same synthetic-same-process zero-key rationale as the
                // Offer case above.
                uint8_t zeroKey[32] = {0};
                signal2sip_call_received_answer(self.handle, self.otherName, callId, 1, payload, payloadLen, zeroKey,
                                                 zeroKey);
                break;
            }
            case MsgType::Ice:
                signal2sip_call_received_ice(self.handle, self.otherName, callId, 1, payload, payloadLen);
                break;
            case MsgType::Ready:
                self.otherReady = true;
                break;
        }
    }
}

// peerA: plain RingRTC caller - pushes a tone, then measures what comes
// back on its own playout after the round trip through peerB's SIP leg.
int runPeerA(int sockFd) {
    LocalPeer peer;
    peer.name = "peerA";
    peer.otherName = "peerB";
    peer.sockFd = sockFd;

    signal2sip_init_logging();
    peer.handle = signal2sip_call_manager_create(makeCallbacks(peer));
    if (!peer.handle) {
        std::cerr << "[peerA] FAIL: could not create call manager\n";
        return 1;
    }
    std::cout << "[peerA] PASS: created call manager\n";

    std::thread reader(signalingReaderLoop, std::ref(peer));

    // A std::thread destructing while still joinable calls std::terminate()
    // (not catchable) - every early return below must join `reader` first.
    // Real bug hit live: an early return here previously skipped straight
    // past the join() at the tail of this function, aborting the whole
    // process while `reader` was still blocked in recv().
    uint64_t callId = signal2sip_call_start_outgoing(peer.handle, "peerB", 1);
    if (callId == 0) {
        std::cerr << "[peerA] FAIL: signal2sip_call_start_outgoing failed\n";
        shutdown(sockFd, SHUT_RDWR);
        reader.join();
        return 1;
    }
    std::cout << "[peerA] PASS: started outgoing call, callId=" << callId << "\n";

    if (!waitForState(peer, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000)) {
        std::cerr << "[peerA] FAIL: never reached Connected (last state=" << peer.lastState.load() << ")\n";
        shutdown(sockFd, SHUT_RDWR);
        reader.join();
        return 1;
    }
    std::cout << "[peerA] PASS: reached Connected\n";

    sendMessage(peer, MsgType::Ready, callId, nullptr, 0);
    // peerB needs real time to register with DPDZK and get the SIP call
    // CONFIRMED before it's meaningful for peerA to start pushing tone -
    // give it a generous window (FreePBX's *43 greeting alone runs a few
    // seconds).
    if (!waitForOtherReady(peer, 30000)) {
        std::cerr << "[peerA] FAIL: peerB never signaled ready\n";
        shutdown(sockFd, SHUT_RDWR);
        reader.join();
        return 1;
    }

    const int sampleRate = 48000;
    const int toneHz = 440;
    const int totalSamples = sampleRate * 10; // 10s - covers FreePBX's greeting + echo window
    std::vector<int16_t> tone(totalSamples);
    for (int i = 0; i < totalSamples; i++) {
        tone[i] = static_cast<int16_t>(8000.0 * std::sin(2.0 * M_PI * toneHz * i / sampleRate));
    }

    std::vector<int16_t> received;
    received.reserve(totalSamples * 2);
    const int chunk = 480; // 10ms
    for (int offset = 0; offset < totalSamples; offset += chunk) {
        int n = std::min(chunk, totalSamples - offset);
        signal2sip_push_recorded_samples(peer.handle, tone.data() + offset, n);

        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(peer.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "[peerA] pulled " << received.size() << " samples\n";
    double sumSquares = 0;
    for (int16_t s : received) sumSquares += static_cast<double>(s) * s;
    double rms = received.empty() ? 0.0 : std::sqrt(sumSquares / received.size());
    std::cout << "[peerA] RMS of received (echoed) audio: " << rms << "\n";

    bool audioFlowed = received.size() > static_cast<size_t>(sampleRate) && rms > 20.0;
    std::cout << (audioFlowed ? "PASS" : "FAIL")
               << ": tone round-tripped through peerB's real SIP leg + DPDZK's *43 echo\n";

    signal2sip_call_hangup(peer.handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    signal2sip_call_manager_destroy(peer.handle);
    shutdown(sockFd, SHUT_RDWR);
    reader.join();
    return audioFlowed ? 0 : 1;
}

// peerB: RingRTC callee bridged to a real SIP call via RingRtcSipBridge.
// Adapts spike4/pjsip-echo-test.cpp's proven Account/Call/
// onCallMediaState pattern - same digest-auth registration and *43 dial -
// but startTransmit()s the RingRtcSipBridge's ports instead of a real
// sound device.
int runPeerB(int sockFd, const std::string& host, const std::string& user, const std::string& password) {
    LocalPeer peer;
    peer.name = "peerB";
    peer.otherName = "peerA";
    peer.sockFd = sockFd;

    signal2sip_init_logging();
    peer.handle = signal2sip_call_manager_create(makeCallbacks(peer));
    if (!peer.handle) {
        std::cerr << "[peerB] FAIL: could not create call manager\n";
        return 1;
    }
    std::cout << "[peerB] PASS: created call manager\n";

    std::thread reader(signalingReaderLoop, std::ref(peer));

    if (!waitForState(peer, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000)) {
        std::cerr << "[peerB] FAIL: never reached Connected (last state=" << peer.lastState.load() << ")\n";
        return 1;
    }
    std::cout << "[peerB] PASS: reached Connected\n";

    // Constructed only after the pjsua2 Endpoint is up (see below) - its
    // ports' constructors call into PJSUA global state (pjsua_pool_create,
    // AudioMedia::registerMediaPort()) that doesn't exist yet before
    // libCreate()/libInit()/libStart(). Constructing it earlier crashed
    // with SIGABRT and zero diagnostic output (confirmed live).
    std::unique_ptr<voip::RingRtcSipBridge> bridge;

    using namespace pj;
    std::atomic<bool> sipConfirmed{false};
    std::atomic<bool> sipDisconnected{false};

    class BridgeCall : public Call {
    public:
        BridgeCall(Account& acc, voip::RingRtcSipBridge& bridge, std::atomic<bool>& confirmed,
                   std::atomic<bool>& disconnected)
            : Call(acc), bridge_(bridge), confirmed_(confirmed), disconnected_(disconnected) {}

        void onCallState(OnCallStateParam&) override {
            CallInfo ci = getInfo();
            std::cout << "[peerB][sip] call state=" << ci.stateText << " (" << ci.state << ")\n";
            if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
                confirmed_ = true;
            } else if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
                disconnected_ = true;
            }
        }

        // This build's PJSIP conference bridge is the non-resampling
        // "switchboard" variant - pjsua_conf_connect() between ports of
        // different clock rates fails outright with PJMEDIA_ENOTCOMPATIBLE
        // (confirmed live: DPDZK's *43 test extension only offers PCMU/
        // 8000, while RingRtcSipBridge's ports are fixed at 48kHz to
        // match RingRTC's raw-PCM ADM). Rather than forcing the call to
        // negotiate 48kHz (tried first - DPDZK's Asterisk doesn't support
        // any wideband codec on this extension, real 488 Not Acceptable
        // Here), wrap each of our ports in a pjmedia_resample_port at the
        // call's actual negotiated rate and connect THAT to the call
        // instead - matches what a real gateway needs anyway for any
        // 8kHz PSTN/SIP trunk.
        void onCallMediaState(OnCallMediaStateParam&) override {
            CallInfo ci = getInfo();
            for (unsigned i = 0; i < ci.media.size(); i++) {
                if (ci.media[i].type == PJMEDIA_TYPE_AUDIO && getMedia(i)) {
                    auto* aud = static_cast<AudioMedia*>(getMedia(i));
                    unsigned callRate = aud->getPortInfo().format.clockRate;
                    std::cout << "[peerB][sip] call negotiated clock rate: " << callRate << "\n";

                    pj_pool_t* pool = pjsua_pool_create("resample", 2048, 512);

                    pjmedia_port* inResample = nullptr;
                    pj_status_t st1 = pjmedia_resample_port_create(
                        pool, bridge_.InputPjmediaPort(), callRate, 0, &inResample);
                    pjsua_conf_port_id inResampleId = PJSUA_INVALID_ID;
                    pj_status_t st2 = pjsua_conf_add_port(pool, inResample, &inResampleId);
                    pj_status_t st3 = pjsua_conf_connect(aud->getPortId(), inResampleId);

                    pjmedia_port* outResample = nullptr;
                    pj_status_t st4 = pjmedia_resample_port_create(
                        pool, bridge_.OutputPjmediaPort(), callRate, 0, &outResample);
                    pjsua_conf_port_id outResampleId = PJSUA_INVALID_ID;
                    pj_status_t st5 = pjsua_conf_add_port(pool, outResample, &outResampleId);
                    pj_status_t st6 = pjsua_conf_connect(outResampleId, aud->getPortId());

                    std::cout << "[peerB][sip] audio media " << i << " wired to RingRtcSipBridge via resample ports"
                               << " (status: in_create=" << st1 << " in_add=" << st2 << " in_connect=" << st3
                               << " out_create=" << st4 << " out_add=" << st5 << " out_connect=" << st6 << ")\n";
                }
            }
        }

    private:
        voip::RingRtcSipBridge& bridge_;
        std::atomic<bool>& confirmed_;
        std::atomic<bool>& disconnected_;
    };

    class BridgeAccount : public Account {
    public:
        std::atomic<bool> registered{false};
        void onRegState(OnRegStateParam&) override {
            AccountInfo ai = getInfo();
            std::cout << "[peerB][sip] reg state active=" << ai.regIsActive << "\n";
            if (ai.regIsActive) registered = true;
        }
    };

    // sipResult tracks the SIP-side outcome; the cleanup below (hangup,
    // shutdown(sockFd), reader.join()) must run on EVERY exit path,
    // including an uncaught exception - a std::thread destructing while
    // still joinable calls std::terminate() (not a catchable exception,
    // the C++ standard mandates this), which is exactly what happened
    // live the first time this used `try { ... } catch (Error&) { return
    // 1; }`: some non-pj::Error exception (never pinned down exactly -
    // not worth the archaeology once the real fix was obvious) skipped
    // past the explicit reader.join() at the tail of this function
    // entirely, and `reader` (still blocked in recv(), confirmed via gdb
    // - the thread was very much alive) aborted the whole process.
    int sipResult = 1;
    Endpoint ep;
    try {
        ep.libCreate();
        EpConfig epConfig;
        epConfig.medConfig.ecTailLen = 0;
        epConfig.medConfig.noVad = true;
        // Matches tg2sip-webrtc/tg2sip/sip.cpp exactly - same shared
        // /usr/local pjproject install, proven working there. Omitting
        // these (this project's first attempt) made libInit() itself fail
        // with a libsrtp "unsupported parameter" bad_param error
        // (PJMEDIA_ERRNO_FROM_LIBSRTP(err_status_bad_param), status
        // 259801) - never fully root-caused at the libsrtp level, just
        // matched the known-good config instead of digging further.
        epConfig.medConfig.audioFramePtime = 10;
        epConfig.medConfig.ptime = 10;
        epConfig.medConfig.clockRate = 48000; // must match RingRtcSipBridge's ports
        ep.libInit(epConfig);
        // Matches tg2sip-webrtc/tg2sip/sip.cpp exactly. Without this,
        // pjsua's own internal media-switchboard logic (NOT anything we
        // wire via pjsua2's AudioMedia::startTransmit()) tries to connect
        // the call to a REAL sound device on every media update, failing
        // (PJMEDIA_EAUD_NODEFDEV, "Unable to find default audio device")
        // in this headless environment - confirmed live: real SIP call to
        // DPDZK's *43 negotiated fine (200 OK, SDP done) up to this exact
        // point. setNullDev() gives it a fake device that always
        // "succeeds" instead, and never touches our own ring-buffer ports.
        ep.audDevManager().setNullDev();

        // NOT forcing a 48kHz codec here (tried first, matching
        // tg2sip-webrtc's approach - see BridgeCall::onCallMediaState's
        // comment for why that doesn't work against this specific target:
        // DPDZK's *43 test extension only offers PCMU/8000, real SIP 488
        // Not Acceptable Here when a wideband-only offer is forced).
        // Accept whatever the call negotiates and resample per-call
        // instead.

        TransportConfig tcfg;
        tcfg.port = 5063; // distinct from other spike4/gateway test ports
        ep.transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
        ep.libStart();

        bridge = std::make_unique<voip::RingRtcSipBridge>(peer.handle);

        AccountConfig acfg;
        acfg.idUri = "sip:" + user + "@" + host;
        acfg.regConfig.registrarUri = "sip:" + host;
        AuthCredInfo cred("digest", "*", user, 0, password);
        acfg.sipConfig.authCreds.push_back(cred);

        BridgeAccount acc;
        acc.create(acfg);

        std::cout << "[peerB] waiting for SIP registration...\n";
        for (int i = 0; i < 100 && !acc.registered.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!acc.registered.load()) {
            std::cerr << "[peerB] FAIL: SIP registration did not complete in time\n";
        } else {
            std::cout << "[peerB] PASS: SIP registered\n";

            std::string destUri = "sip:*43@" + host;
            std::cout << "[peerB][sip] placing call to " << destUri << "\n";
            auto* call = new BridgeCall(acc, *bridge, sipConfirmed, sipDisconnected);
            CallOpParam prm(true);
            prm.opt.audioCount = 1;
            prm.opt.videoCount = 0;
            call->makeCall(destUri, prm);

            for (int i = 0; i < 100 && !sipConfirmed.load() && !sipDisconnected.load(); i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            if (!sipConfirmed.load()) {
                std::cerr << "[peerB] FAIL: SIP call to *43 never reached CONFIRMED\n";
                delete call;
            } else {
                std::cout << "[peerB] PASS: SIP call to *43 CONFIRMED\n";

                bridge->Start();
                sendMessage(peer, MsgType::Ready, peer.callId.load(), nullptr, 0);
                waitForOtherReady(peer, 5000); // best-effort, doesn't gate anything on this side

                // Let the round trip run for as long as peerA's tone-push
                // loop (10s) plus slack for FreePBX's greeting/echo timing.
                std::this_thread::sleep_for(std::chrono::milliseconds(15000));

                bridge->Stop();
                CallOpParam hprm;
                try { call->hangup(hprm); } catch (...) {}
                // hangup() is async (just sends BYE) - deleting the C++
                // Call object immediately, before the underlying pjsip
                // invite session/media has actually finished tearing
                // down, left a stale AudioMedia pointer in pjsua2's own
                // Endpoint::mediaList, which then double-freed it in
                // Endpoint::~Endpoint()'s cleanup loop
                // (SIGSEGV in libDestroy() at "delete cur_media", confirmed
                // live via gdb). Wait for the real DISCONNECTED state
                // first.
                for (int i = 0; i < 50 && !sipDisconnected.load(); i++) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                delete call;
                sipResult = 0;
            }
        }
    } catch (Error& err) {
        std::cerr << "[peerB] FAIL: pjsua2 error: " << err.info() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "[peerB] FAIL: exception: " << e.what() << "\n";
    } catch (...) {
        std::cerr << "[peerB] FAIL: unknown exception\n";
    }

    // Must be destroyed while `ep` (declared after `bridge`, so destroyed
    // before it in normal reverse-declaration-order cleanup) is still
    // alive - SoftwareAudioInput/Output's destructors call
    // unregisterMediaPort(), which needs pjsua2's endpoint state to still
    // exist. Explicit reset() here instead of relying on destruction order.
    bridge.reset();

    signal2sip_call_hangup(peer.handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    signal2sip_call_manager_destroy(peer.handle);
    shutdown(sockFd, SHUT_RDWR);
    reader.join();
    return sipResult;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "usage: pjsip_ringrtc_echo_test <sip_host> <extension> <password>\n";
        return 1;
    }
    std::string host = argv[1];
    std::string user = argv[2];
    std::string password = argv[3];

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0) {
        std::cerr << "FAIL: socketpair() failed: " << strerror(errno) << "\n";
        return 1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "FAIL: fork() failed: " << strerror(errno) << "\n";
        return 1;
    }

    if (pid == 0) {
        close(fds[0]);
        // Both processes share the same inherited stdout/stderr fds from
        // fork() - writing to them concurrently from two processes isn't
        // synchronized, and interleaves at the byte level (not just line
        // level), corrupting both logs. Give the child its own separate
        // log file instead, redirecting at the fd level (not freopen()'s
        // FILE* level) since std::cout's streambuf may have already
        // cached the original fd 1.
        int logFd = open("/tmp/pjsip_ringrtc_echo_test_peerB.log", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (logFd >= 0) {
            dup2(logFd, STDOUT_FILENO);
            dup2(logFd, STDERR_FILENO);
            close(logFd);
        }
        // Unbuffered, not just line-buffered - if this process crashes
        // (SIGABRT/SIGSEGV) the normal std::cout.flush() cleanup path never
        // runs, and a redirected (non-tty) stdout is fully buffered by
        // default, so every cout line since the last flush would otherwise
        // vanish silently. Confirmed live: an earlier crash produced zero
        // "[peerB]" lines in this log despite real RingRTC/pjsip activity
        // clearly having happened.
        setvbuf(stdout, nullptr, _IONBF, 0);
        int result = runPeerB(fds[1], host, user, password);
        std::cout.flush();
        std::cerr.flush();
        _exit(result);
    }

    close(fds[1]);
    int peerAResult = runPeerA(fds[0]);

    int childStatus = 0;
    if (waitpid(pid, &childStatus, 0) < 0) {
        std::cerr << "FAIL: waitpid() failed: " << strerror(errno) << "\n";
        return 1;
    }
    int peerBResult = WIFEXITED(childStatus) ? WEXITSTATUS(childStatus) : 1;

    return (peerAResult == 0 && peerBResult == 0) ? 0 : 1;
}
