#include "ringrtc_sip_bridge.h"

using namespace voip;

RingRtcSipBridge::RingRtcSipBridge(Signal2sipCallManagerHandle *handle) : handle_(handle) {}

RingRtcSipBridge::~RingRtcSipBridge() {
    Stop();

    // Found live 2026-08-06: without this, a real SIGSEGV - PJMEDIA's own
    // clock_thread (a separate, independent realtime thread that keeps
    // ticking at 48kHz regardless of any C++ object lifetime) called
    // resample_put_frame() on a resample port wireBridgeAudio() (main.cpp)
    // had wired to InputPjmediaPort()/OutputPjmediaPort() but never
    // removed - and by the time this destructor's implicit epilogue got
    // around to destroying audio_input_/audio_output_ below (freeing
    // their pjmedia_port + pool), the resample port was STILL registered
    // in the pjsua conference bridge and still forwarding frames into now
    // -freed memory. `pjsua_conf_remove_port()` must run - and the
    // resample ports must actually stop being driven - before
    // audio_input_/audio_output_'s own destructors run just below, which
    // is exactly why this is in the destructor BODY (runs first) rather
    // than a separate explicit call site: correct ordering is guaranteed
    // regardless of which teardown path (stopSipBridge() vs
    // stopIncomingSipCall()) got here.
    if (resample_pool_) {
        pjsua_conf_remove_port(in_resample_id_);
        pjsua_conf_remove_port(out_resample_id_);
        pj_pool_release(resample_pool_);
        resample_pool_ = nullptr;
    }
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
