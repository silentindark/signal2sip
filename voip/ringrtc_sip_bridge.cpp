#include "ringrtc_sip_bridge.h"

using namespace voip;

RingRtcSipBridge::RingRtcSipBridge(Signal2sipCallManagerHandle *handle) : handle_(handle) {}

RingRtcSipBridge::~RingRtcSipBridge() {
    Stop();
}

void RingRtcSipBridge::Start() {
    if (feeder_running_.exchange(true)) return; // already running
    audio_input_.Start();
    audio_output_.Start();
    feeder_thread_ = std::thread(&RingRtcSipBridge::FeederLoop, this);
}

void RingRtcSipBridge::Stop() {
    if (!feeder_running_.exchange(false)) return; // wasn't running
    if (feeder_thread_.joinable()) feeder_thread_.join();
    audio_input_.Stop();
    audio_output_.Stop();
}

void RingRtcSipBridge::FeederLoop() {
    int16_t mic_scratch[kSamplesPerFrame];
    int16_t playout_scratch[kSamplesPerFrame];
    auto next_deadline = std::chrono::steady_clock::now();

    while (feeder_running_.load(std::memory_order_relaxed)) {
        next_deadline += std::chrono::milliseconds(10);
        std::this_thread::sleep_until(next_deadline);

        // SIP -> RingRTC: whatever PJSIP delivered into mic_buffer_ this
        // tick (padded with silence on underrun by RingBuffer::pop itself).
        mic_buffer_->pop(mic_scratch, kSamplesPerFrame);
        signal2sip_push_recorded_samples(handle_, mic_scratch, kSamplesPerFrame);

        // RingRTC -> SIP: pull whatever's been decoded since the last tick
        // and hand it to PJSIP via playout_buffer_. May return fewer than
        // kSamplesPerFrame (e.g. right after call start); pad the rest with
        // silence so SoftwareAudioOutput always has a full frame to hand
        // PJSIP - it always pops kSamplesPerFrame regardless.
        size_t got = signal2sip_pull_playout_samples(handle_, playout_scratch, kSamplesPerFrame);
        playout_buffer_->push(playout_scratch, got);
    }
}
