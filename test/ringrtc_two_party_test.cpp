// Milestone E live verification (see
// /home/vlad/.claude/plans/jiggly-mapping-plum.md and this project's
// memory project_signal2sip_milestone_e_research): two SEPARATE PROCESSES
// (via fork()), each with its own single CallManager<NativePlatform> (via
// the new native/ringrtc/signal2sip_ringrtc.h C ABI), relaying
// received_offer/received_answer/received_ice/message_sent to each other
// over a Unix domain socket (no real network - a synthetic signaling
// relay, same pattern as this project's earlier dummy-identity spikes),
// confirming CallState reaches Connected on both sides and that a
// synthetic tone pushed into one side's raw-PCM ADM (Milestone D) comes
// out the other side's.
//
// Two SEPARATE PROCESSES, not two CallManagers in one process like this
// test originally did: ringrtc's own C++ RFFI shim
// (ringrtc/rffi/src/audio_device.cc, real upstream Signal code, not ours)
// keeps its registered AudioTransport* in a single process-wide global
// (`AUDIO_TRANSPORT`), not per-ADM-instance. Two CallManagers in the same
// process silently clobber each other's registration - whichever
// RegisterAudioCallback() call happens last "wins", and the other
// instance's mic/speaker callbacks are silently never invoked again. This
// isn't a production bug (this project's real gateway runs one
// CallManager per OS process, one process per account - see this
// project's memory project_signal2sip_cpp_rewrite), only a two-managers-
// in-one-process synthetic-test artifact - found and root-caused via gdb
// + reading ringrtc's own rffi source on 2026-07-31, see this project's
// memory project_signal2sip_milestone_e_progress for the full trace.
// Splitting into two real processes both fixes the test and matches the
// real architecture more closely.

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

#include "../ringrtc/signal2sip_ringrtc.h"

namespace {

// Message framing over the AF_UNIX SOCK_SEQPACKET socket connecting the
// two processes - SEQPACKET preserves message boundaries (unlike
// SOCK_STREAM), so no length-prefixing is needed: one write() = one
// message, one recv() = one message.
enum class MsgType : uint8_t { Offer = 0, Answer = 1, Ice = 2, Ready = 3 };

constexpr size_t kMaxMsg = 4096;
constexpr size_t kHeaderLen = 1 + sizeof(uint64_t); // type + callId

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

void onSendOffer(void* ctx, const char* /*remotePeerId*/, uint64_t callId, int32_t /*mediaType*/,
                  const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    self->callId = callId;
    std::cout << "[" << self->name << "] send_offer (len=" << opaqueLen << ") -> " << self->otherName << "\n";
    sendMessage(*self, MsgType::Offer, callId, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendAnswer(void* ctx, const char* /*remotePeerId*/, uint64_t callId, const uint8_t* opaque,
                   size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    std::cout << "[" << self->name << "] send_answer (len=" << opaqueLen << ") -> " << self->otherName << "\n";
    sendMessage(*self, MsgType::Answer, callId, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendIce(void* ctx, const char* /*remotePeerId*/, uint64_t callId, bool /*hasDeviceId*/,
               uint32_t /*deviceId*/, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    sendMessage(*self, MsgType::Ice, callId, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendHangup(void* ctx, const char* /*remotePeerId*/, uint64_t callId, int32_t /*hangupType*/,
                   uint32_t /*hangupDeviceId*/) {
    auto* self = static_cast<LocalPeer*>(ctx);
    std::cout << "[" << self->name << "] send_hangup\n";
    signal2sip_call_message_sent(self->handle, callId);
}

void onCallState(void* ctx, const char* /*remotePeerId*/, uint64_t callId, int32_t state) {
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
        // Must wait for Ringing (connected && !accepted) before accepting -
        // calling accept_call() right after proceed() races the call FSM
        // and gets silently dropped ("Unexpected event AcceptCall, while
        // in state ConnectingBeforeAccepted").
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

// Reads and dispatches signaling messages from the other process until the
// socket closes (peer process exited) or a read error occurs.
void signalingReaderLoop(LocalPeer& self) {
    std::vector<uint8_t> buf(kMaxMsg);
    for (;;) {
        ssize_t n = recv(self.sockFd, buf.data(), buf.size(), 0);
        if (n <= 0) return; // peer closed or error - exit quietly, main loop has its own timeouts
        if (static_cast<size_t>(n) < kHeaderLen) continue;

        auto type = static_cast<MsgType>(buf[0]);
        uint64_t callId;
        std::memcpy(&callId, buf.data() + 1, sizeof(callId));
        const uint8_t* payload = buf.data() + kHeaderLen;
        size_t payloadLen = static_cast<size_t>(n) - kHeaderLen;

        switch (type) {
            case MsgType::Offer:
                signal2sip_call_received_offer(self.handle, self.otherName, callId, 1, 1, payload, payloadLen);
                break;
            case MsgType::Answer:
                signal2sip_call_received_answer(self.handle, self.otherName, callId, 1, payload, payloadLen);
                break;
            case MsgType::Ice:
                signal2sip_call_received_ice(self.handle, self.otherName, callId, 1, payload, payloadLen);
                break;
            case MsgType::Ready:
                self.otherReady = true;
                break;
        }
    }
}

// Runs as peerA (caller): starts the outgoing call, waits for Connected,
// pushes a 440Hz tone into its own "microphone" for 2 real seconds, then
// hangs up. Returns 0 on success, 1 on failure - mirrors the original
// single-process test's PASS/FAIL assertions for the caller side only
// (the callee/receiver side's audio-flowed check runs in runPeerB()).
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
    std::cout << "[peerA] PASS: created call manager with raw-PCM ADM\n";

    std::thread reader(signalingReaderLoop, std::ref(peer));

    uint64_t callId = signal2sip_call_start_outgoing(peer.handle, "peerB", 1);
    if (callId == 0) {
        std::cerr << "[peerA] FAIL: signal2sip_call_start_outgoing failed\n";
        return 1;
    }
    std::cout << "[peerA] PASS: started outgoing call, callId=" << callId << "\n";

    if (!waitForState(peer, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000)) {
        std::cerr << "[peerA] FAIL: never reached Connected (last state=" << peer.lastState.load() << ")\n";
        return 1;
    }
    std::cout << "[peerA] PASS: reached Connected\n";

    sendMessage(peer, MsgType::Ready, callId, nullptr, 0);
    if (!waitForOtherReady(peer, 10000)) {
        std::cerr << "[peerA] FAIL: peerB never signaled ready\n";
        return 1;
    }

    // Push a 440Hz tone (mono, 48kHz, i16) from peerA's "microphone" for 2
    // real seconds, matching WebRTC's own 10ms/480-sample window.
    const int sampleRate = 48000;
    const int toneHz = 440;
    const int totalSamples = sampleRate * 2;
    std::vector<int16_t> tone(totalSamples);
    for (int i = 0; i < totalSamples; i++) {
        tone[i] = static_cast<int16_t>(8000.0 * std::sin(2.0 * M_PI * toneHz * i / sampleRate));
    }

    const int chunk = 480; // 10ms
    for (int offset = 0; offset < totalSamples; offset += chunk) {
        int n = std::min(chunk, totalSamples - offset);
        signal2sip_push_recorded_samples(peer.handle, tone.data() + offset, n);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Give peerB a little extra time to drain/decode before hanging up.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    signal2sip_call_hangup(peer.handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    signal2sip_call_manager_destroy(peer.handle);
    shutdown(sockFd, SHUT_RDWR);
    reader.join();
    return 0;
}

// Runs as peerB (callee): waits for the offer to arrive, waits for
// Connected, pulls playout samples from its own "speaker" for the same
// window peerA is pushing into its mic, and computes RMS - this is where
// the actual pass/fail verdict for the audio-flow test comes from.
int runPeerB(int sockFd) {
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
    std::cout << "[peerB] PASS: created call manager with raw-PCM ADM\n";

    std::thread reader(signalingReaderLoop, std::ref(peer));

    if (!waitForState(peer, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000)) {
        std::cerr << "[peerB] FAIL: never reached Connected (last state=" << peer.lastState.load() << ")\n";
        return 1;
    }
    std::cout << "[peerB] PASS: reached Connected\n";

    sendMessage(peer, MsgType::Ready, peer.callId.load(), nullptr, 0);
    if (!waitForOtherReady(peer, 10000)) {
        std::cerr << "[peerB] FAIL: peerA never signaled ready\n";
        return 1;
    }

    const int sampleRate = 48000;
    const int totalSamples = sampleRate * 2;
    const int chunk = 480; // 10ms

    std::vector<int16_t> received;
    received.reserve(totalSamples * 2);
    for (int offset = 0; offset < totalSamples; offset += chunk) {
        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(peer.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Drain a bit more in case of jitter/decoder latency.
    for (int i = 0; i < 100; i++) {
        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(peer.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "[peerB] pulled " << received.size() << " samples\n";
    double sumSquares = 0;
    for (int16_t s : received) sumSquares += static_cast<double>(s) * s;
    double rms = received.empty() ? 0.0 : std::sqrt(sumSquares / received.size());
    std::cout << "[peerB] RMS of received audio: " << rms << "\n";

    bool audioFlowed = received.size() > static_cast<size_t>(sampleRate / 2) && rms > 50.0;
    std::cout << (audioFlowed ? "PASS" : "FAIL") << ": synthetic tone flowed from peerA's mic to peerB's speaker\n";

    signal2sip_call_hangup(peer.handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    signal2sip_call_manager_destroy(peer.handle);
    shutdown(sockFd, SHUT_RDWR);
    reader.join();
    return audioFlowed ? 0 : 1;
}

} // namespace

int main() {
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
        // Child: peerB (callee). std::cout is fully buffered on a non-tty
        // stream (e.g. redirected to a file) - _exit() skips iostream/stdio
        // flushing entirely, which silently discarded all of peerB's
        // buffered output (including the PASS/FAIL/RMS verdict) the first
        // time this ran. Flush explicitly before _exit().
        close(fds[0]);
        int result = runPeerB(fds[1]);
        std::cout.flush();
        std::cerr.flush();
        _exit(result);
    }

    // Parent: peerA (caller).
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
