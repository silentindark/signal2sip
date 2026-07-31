// Milestone E live verification (see
// /home/vlad/.claude/plans/jiggly-mapping-plum.md and this project's
// memory project_signal2sip_milestone_e_research): two in-process
// CallManager<NativePlatform> instances (via the new
// native/ringrtc/signal2sip_ringrtc.h C ABI), wired directly to each
// other's received_offer/received_answer/received_ice (no real network -
// a synthetic signaling relay, same pattern as this project's earlier
// dummy-identity spikes), confirming CallState reaches Connected on both
// sides and that a synthetic tone pushed into one side's raw-PCM ADM
// (Milestone D) comes out the other side's.

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <iostream>
#include <thread>
#include <vector>

#include "../ringrtc/signal2sip_ringrtc.h"

namespace {

struct Peer {
    const char* name;
    Signal2sipCallManagerHandle* handle = nullptr;
    Peer* other = nullptr;
    std::atomic<uint64_t> callId{0};
    std::atomic<int32_t> lastState{-1};
    std::atomic<bool> isCallee{false};
};

// Every onSend* callback below must call signal2sip_call_message_sent()
// once it has finished "delivering" the message (here, a direct synchronous
// call into the other peer's handle - always succeeds) - RingRTC's own
// signaling queue serializes messages per call and will not invoke the
// next send_* callback (e.g. the next ICE candidate) until this is called.
// Missing it was a real bug: only the first message per call (the offer/
// answer) ever went out, every ICE candidate queued up forever, and the
// call stalled in ConnectingBeforeAccepted until RingRTC's own ~60s
// CallTimeout ended it.

void onSendOffer(void* ctx, const char* /*remotePeerId*/, uint64_t callId, int32_t /*mediaType*/,
                  const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<Peer*>(ctx);
    self->callId = callId;
    std::cout << "[" << self->name << "] send_offer (len=" << opaqueLen << ") -> " << self->other->name << "\n";
    signal2sip_call_received_offer(self->other->handle, self->name, callId, 1, 1, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendAnswer(void* ctx, const char* /*remotePeerId*/, uint64_t callId, const uint8_t* opaque,
                   size_t opaqueLen) {
    auto* self = static_cast<Peer*>(ctx);
    std::cout << "[" << self->name << "] send_answer (len=" << opaqueLen << ") -> " << self->other->name << "\n";
    signal2sip_call_received_answer(self->other->handle, self->name, callId, 1, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendIce(void* ctx, const char* /*remotePeerId*/, uint64_t callId, bool /*hasDeviceId*/,
               uint32_t /*deviceId*/, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<Peer*>(ctx);
    signal2sip_call_received_ice(self->other->handle, self->name, callId, 1, opaque, opaqueLen);
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendHangup(void* ctx, const char* /*remotePeerId*/, uint64_t callId, int32_t /*hangupType*/,
                   uint32_t /*hangupDeviceId*/) {
    auto* self = static_cast<Peer*>(ctx);
    std::cout << "[" << self->name << "] send_hangup\n";
    signal2sip_call_message_sent(self->handle, callId);
}

void onCallState(void* ctx, const char* /*remotePeerId*/, uint64_t callId, int32_t state) {
    auto* self = static_cast<Peer*>(ctx);
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

Signal2sipCallbacks makeCallbacks(Peer& peer) {
    Signal2sipCallbacks cb{};
    cb.context = &peer;
    cb.send_offer = onSendOffer;
    cb.send_answer = onSendAnswer;
    cb.send_ice = onSendIce;
    cb.send_hangup = onSendHangup;
    cb.call_state = onCallState;
    return cb;
}

bool waitForState(Peer& peer, int32_t state, int timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (peer.lastState.load() == state) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return false;
}

} // namespace

int main() {
    signal2sip_init_logging();

    Peer a{"peerA"};
    Peer b{"peerB"};
    a.other = &b;
    b.other = &a;

    a.handle = signal2sip_call_manager_create(makeCallbacks(a));
    b.handle = signal2sip_call_manager_create(makeCallbacks(b));
    if (!a.handle || !b.handle) {
        std::cerr << "FAIL: could not create call manager(s)\n";
        return 1;
    }
    std::cout << "PASS: created two call managers with raw-PCM ADMs\n";

    uint64_t callId = signal2sip_call_start_outgoing(a.handle, "peerB", 1);
    if (callId == 0) {
        std::cerr << "FAIL: signal2sip_call_start_outgoing failed\n";
        return 1;
    }
    std::cout << "PASS: started outgoing call, callId=" << callId << "\n";

    if (!waitForState(a, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000)) {
        std::cerr << "FAIL: peerA never reached Connected (last state=" << a.lastState.load() << ")\n";
        return 1;
    }
    std::cout << "PASS: peerA reached Connected\n";
    if (!waitForState(b, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000)) {
        std::cerr << "FAIL: peerB never reached Connected (last state=" << b.lastState.load() << ")\n";
        return 1;
    }
    std::cout << "PASS: peerB reached Connected\n";

    // Push a 440Hz tone (mono, 48kHz, i16) from peerA's "microphone" for 2
    // real seconds, matching WebRTC's own 10ms/480-sample window.
    const int sampleRate = 48000;
    const int toneHz = 440;
    const int totalSamples = sampleRate * 2;
    std::vector<int16_t> tone(totalSamples);
    for (int i = 0; i < totalSamples; i++) {
        tone[i] = static_cast<int16_t>(8000.0 * std::sin(2.0 * M_PI * toneHz * i / sampleRate));
    }

    std::vector<int16_t> received;
    received.reserve(totalSamples * 2);
    const int chunk = 480; // 10ms
    for (int offset = 0; offset < totalSamples; offset += chunk) {
        int n = std::min(chunk, totalSamples - offset);
        signal2sip_push_recorded_samples(a.handle, tone.data() + offset, n);

        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(b.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Drain a bit more in case of jitter/decoder latency.
    for (int i = 0; i < 50; i++) {
        int16_t buf[chunk];
        size_t got = signal2sip_pull_playout_samples(b.handle, buf, chunk);
        if (got > 0) received.insert(received.end(), buf, buf + got);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::cout << "pulled " << received.size() << " samples from peerB\n";
    double sumSquares = 0;
    for (int16_t s : received) sumSquares += static_cast<double>(s) * s;
    double rms = received.empty() ? 0.0 : std::sqrt(sumSquares / received.size());
    std::cout << "RMS of received audio: " << rms << "\n";

    bool audioFlowed = received.size() > static_cast<size_t>(sampleRate / 2) && rms > 50.0;
    std::cout << (audioFlowed ? "PASS" : "FAIL") << ": synthetic tone flowed from peerA's mic to peerB's speaker\n";

    signal2sip_call_hangup(a.handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    signal2sip_call_manager_destroy(a.handle);
    signal2sip_call_manager_destroy(b.handle);

    return audioFlowed ? 0 : 1;
}
