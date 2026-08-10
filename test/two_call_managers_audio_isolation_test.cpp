// §0 verification for the single-process multi-account daemon refactor
// (/home/vlad/.claude/plans/fancy-swimming-church.md): confirms two
// INDEPENDENT Signal2sipCallManagerHandles, each with their own raw-PCM
// ADM, can run two SIMULTANEOUS active calls in one process without
// audio crossing over between them.
//
// Before today's fix, this was impossible in principle: ringrtc's own
// C++ RFFI shim (../webrtc/ringrtc/rffi/src/audio_device.cc, a sibling checkout of ../ringrtc,
// real upstream Signal code) kept its registered AudioTransport* in a
// single process-wide global (AUDIO_TRANSPORT) that every
// RingRTCAudioDeviceModule instance's RegisterAudioCallback() overwrote -
// whichever call registered last "won", and the other call's raw-PCM
// threads (Rust_recordedDataIsAvailable/Rust_needMorePlayData) would
// silently read/write through the WRONG registered transport. See
// ringrtc_two_party_test.cpp's own top-of-file comment for the direct
// evidence of this (that test used to run two CallManagers in one
// process too, and was split into two OS processes specifically to work
// around this bug - see this project's memory
// project_signal2sip_milestone_e_progress). Fixed by making
// AUDIO_TRANSPORT per-instance (a small registry keyed by each
// RingRTCAudioDeviceModule's own `adm_borrowed` pointer) and adding
// instance-aware Rust_rawPcmRecordedDataIsAvailable/
// Rust_rawPcmNeedMorePlayData entry points that RawPcmAudioDeviceModule
// uses instead of the old global-slot functions (which the cubeb-backed
// ADM path - unused by this project - still uses unmodified).
//
// Two independent call PAIRS (A<->B, C<->D - 4 CallManagers, 4 raw-PCM
// ADMs total) run CONCURRENTLY in this one process, each pushing a
// distinct, easily-verified signal into its caller's "microphone" for
// the same real-time window: pair A/B gets a 440Hz tone, pair C/D gets a
// silence-only feed (nothing pushed at all) - if AUDIO_TRANSPORT were
// still a single global slot, whichever pair's RegisterAudioCallback()
// happened to run last would "win" it, and the OTHER pair's callee would
// receive either the WRONG pair's tone (if it lost) or silence (if the
// winning pair's registration overwrote a callback the other pair's
// threads were still trying to use) - either way, a real, detectable
// mismatch between "which tone was pushed into which pair's mic" and
// "what that pair's callee actually received". Per-instance isolation
// means B receives the real 440Hz tone (non-trivial RMS) while D
// receives silence (near-zero RMS), simultaneously.

#include <sys/socket.h>
#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

#include "../ringrtc/signal2sip_ringrtc.h"

namespace {

// In-process signaling relay between two peers of one call pair - same
// message shape ringrtc_two_party_test.cpp's socket-based relay used,
// just delivered via a thread-safe queue instead of serializing over an
// AF_UNIX socket, since both peers now live in the same process (no IPC
// needed - the whole point of this test).
enum class MsgType : uint8_t { Offer, Answer, Ice, Ready };

struct Message {
    MsgType type;
    uint64_t callId;
    std::vector<uint8_t> payload;
};

class MessageQueue {
public:
    void push(Message msg) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queue_.push_back(std::move(msg));
        }
        cv_.notify_one();
    }

    // Blocks until a message is available or the queue is closed (peer
    // done) - returns false on close.
    bool pop(Message& out) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return closed_ || !queue_.empty(); });
        if (queue_.empty()) return false;
        out = std::move(queue_.front());
        queue_.pop_front();
        return true;
    }

    void close() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        cv_.notify_one();
    }

private:
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<Message> queue_;
    bool closed_ = false;
};

struct LocalPeer {
    const char* name = nullptr;
    const char* otherName = nullptr;
    MessageQueue* outbox = nullptr; // delivered to the other peer's inbox
    MessageQueue inbox;
    Signal2sipCallManagerHandle* handle = nullptr;
    std::atomic<uint64_t> callId{0};
    std::atomic<int32_t> lastState{-1};
    std::atomic<bool> isCallee{false};
    std::atomic<bool> otherReady{false};
};

void onSendOffer(void* ctx, const char*, uint64_t callId, int32_t, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    self->callId = callId;
    self->outbox->push({MsgType::Offer, callId, std::vector<uint8_t>(opaque, opaque + opaqueLen)});
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendAnswer(void* ctx, const char*, uint64_t callId, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    self->outbox->push({MsgType::Answer, callId, std::vector<uint8_t>(opaque, opaque + opaqueLen)});
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendIce(void* ctx, const char*, uint64_t callId, bool, uint32_t, const uint8_t* opaque, size_t opaqueLen) {
    auto* self = static_cast<LocalPeer*>(ctx);
    self->outbox->push({MsgType::Ice, callId, std::vector<uint8_t>(opaque, opaque + opaqueLen)});
    signal2sip_call_message_sent(self->handle, callId);
}

void onSendHangup(void* ctx, const char*, uint64_t callId, int32_t, uint32_t) {
    auto* self = static_cast<LocalPeer*>(ctx);
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

// Runs on its own thread per peer, dispatching messages from the other
// peer of the same pair into this peer's RingRTC handle - mirrors
// ringrtc_two_party_test.cpp's signalingReaderLoop, minus the socket.
void signalingReaderLoop(LocalPeer& self) {
    Message msg;
    while (self.inbox.pop(msg)) {
        uint8_t zeroKey[32] = {0}; // synthetic same-process test, see ringrtc_two_party_test.cpp's rationale
        switch (msg.type) {
            case MsgType::Offer:
                signal2sip_call_received_offer(self.handle, self.otherName, msg.callId, 1, 1, msg.payload.data(),
                                                msg.payload.size(), zeroKey, zeroKey);
                break;
            case MsgType::Answer:
                signal2sip_call_received_answer(self.handle, self.otherName, msg.callId, 1, msg.payload.data(),
                                                 msg.payload.size(), zeroKey, zeroKey);
                break;
            case MsgType::Ice:
                signal2sip_call_received_ice(self.handle, self.otherName, msg.callId, 1, msg.payload.data(),
                                              msg.payload.size());
                break;
            case MsgType::Ready:
                self.otherReady = true;
                break;
        }
    }
}

// One call pair (caller + callee). `toneHz` == 0 means push nothing at
// all into the caller's mic (silence) - used for the second pair to give
// the first pair's tone something unambiguous to be mistaken for if
// AUDIO_TRANSPORT cross-talk were still present.
struct PairResult {
    double calleeRms = -1.0;
    bool reachedConnected = false;
};

PairResult runPair(const char* callerName, const char* calleeName, int toneHz) {
    PairResult result;

    LocalPeer caller;
    caller.name = callerName;
    caller.otherName = calleeName;
    LocalPeer callee;
    callee.name = calleeName;
    callee.otherName = callerName;
    caller.outbox = &callee.inbox;
    callee.outbox = &caller.inbox;

    caller.handle = signal2sip_call_manager_create(makeCallbacks(caller));
    callee.handle = signal2sip_call_manager_create(makeCallbacks(callee));
    if (!caller.handle || !callee.handle) {
        std::cerr << "[" << callerName << "/" << calleeName << "] FAIL: could not create call manager(s)\n";
        return result;
    }

    std::thread callerReader(signalingReaderLoop, std::ref(caller));
    std::thread calleeReader(signalingReaderLoop, std::ref(callee));

    uint64_t callId = signal2sip_call_start_outgoing(caller.handle, calleeName, 1);
    if (callId == 0) {
        std::cerr << "[" << callerName << "] FAIL: signal2sip_call_start_outgoing failed\n";
        caller.inbox.close();
        callee.inbox.close();
        callerReader.join();
        calleeReader.join();
        signal2sip_call_manager_destroy(caller.handle);
        signal2sip_call_manager_destroy(callee.handle);
        return result;
    }

    bool callerConnected = waitForState(caller, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000);
    bool calleeConnected = waitForState(callee, SIGNAL2SIP_CALL_STATE_CONNECTED, 60000);
    result.reachedConnected = callerConnected && calleeConnected;
    if (!result.reachedConnected) {
        std::cerr << "[" << callerName << "/" << calleeName << "] FAIL: never reached Connected (caller="
                   << caller.lastState.load() << " callee=" << callee.lastState.load() << ")\n";
    } else {
        std::cout << "[" << callerName << "/" << calleeName << "] PASS: both reached Connected\n";

        caller.outbox->push({MsgType::Ready, callId, {}});
        callee.outbox->push({MsgType::Ready, callId, {}});
        waitForOtherReady(caller, 10000);
        waitForOtherReady(callee, 10000);

        // Push (or don't, if toneHz==0) for 2 real seconds while pulling
        // from the callee's speaker on a parallel thread, exactly
        // overlapping in time with the other pair's own push/pull window -
        // this concurrency is the whole point of the test.
        const int sampleRate = 48000;
        const int totalSamples = sampleRate * 2;
        const int chunk = 480; // 10ms

        std::vector<int16_t> received;
        std::thread puller([&] {
            received.reserve(totalSamples * 2);
            for (int offset = 0; offset < totalSamples + sampleRate; offset += chunk) { // +1s drain tail
                int16_t buf[chunk];
                size_t got = signal2sip_pull_playout_samples(callee.handle, buf, chunk);
                if (got > 0) received.insert(received.end(), buf, buf + got);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });

        if (toneHz > 0) {
            std::vector<int16_t> tone(totalSamples);
            for (int i = 0; i < totalSamples; i++) {
                tone[i] = static_cast<int16_t>(8000.0 * std::sin(2.0 * M_PI * toneHz * i / sampleRate));
            }
            for (int offset = 0; offset < totalSamples; offset += chunk) {
                int n = std::min(chunk, totalSamples - offset);
                signal2sip_push_recorded_samples(caller.handle, tone.data() + offset, n);
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        } else {
            // Deliberately push nothing - this pair's caller "microphone"
            // stays silent for the whole window.
            std::this_thread::sleep_for(std::chrono::milliseconds(totalSamples * 1000 / sampleRate));
        }

        puller.join();
        double sumSquares = 0;
        for (int16_t s : received) sumSquares += static_cast<double>(s) * s;
        result.calleeRms = received.empty() ? 0.0 : std::sqrt(sumSquares / received.size());
        std::cout << "[" << calleeName << "] pulled " << received.size() << " samples, RMS=" << result.calleeRms
                   << " (caller pushed " << (toneHz > 0 ? "a real tone" : "silence") << ")\n";
    }

    signal2sip_call_hangup(caller.handle);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    caller.inbox.close();
    callee.inbox.close();
    callerReader.join();
    calleeReader.join();
    signal2sip_call_manager_destroy(caller.handle);
    signal2sip_call_manager_destroy(callee.handle);
    return result;
}

} // namespace

int main() {
    signal2sip_init_logging();

    // Run pair A/B (real 440Hz tone) and pair C/D (silence) truly
    // concurrently on separate threads - both pairs' RegisterAudioCallback()
    // calls, and both pairs' raw-PCM playout/recording threads, are live
    // at the same time, the exact scenario that used to silently corrupt
    // audio when AUDIO_TRANSPORT was one process-wide slot.
    PairResult resultAB, resultCD;
    std::thread threadAB([&] { resultAB = runPair("peerA", "peerB", 440); });
    std::thread threadCD([&] { resultCD = runPair("peerC", "peerD", 0); });
    threadAB.join();
    threadCD.join();

    bool ok = true;
    if (!resultAB.reachedConnected || !resultCD.reachedConnected) {
        std::cerr << "FAIL: one or both pairs never connected\n";
        ok = false;
    }
    // peerB (real tone pushed) must show strong, clearly-non-silent audio.
    if (resultAB.calleeRms < 50.0) {
        std::cerr << "FAIL: peerB's RMS (" << resultAB.calleeRms << ") is too low - expected a real 440Hz tone\n";
        ok = false;
    }
    // peerD (nothing pushed) must show silence - if AUDIO_TRANSPORT
    // cross-talk were still present, peerD could instead receive peerA's
    // tone (registrations swapped) or garbage, either way NOT near-zero.
    if (resultCD.calleeRms > 20.0) {
        std::cerr << "FAIL: peerD's RMS (" << resultCD.calleeRms
                   << ") is too high - expected silence, got real audio, likely from the WRONG pair\n";
        ok = false;
    }

    std::cout << (ok ? "PASS" : "FAIL")
               << ": two concurrent CallManager pairs kept their audio isolated in one process\n";
    return ok ? 0 : 1;
}
