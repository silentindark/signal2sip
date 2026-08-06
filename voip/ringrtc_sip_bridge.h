// Milestone F: glues the PJSIP-facing ring-buffer ports (audio_bridge.h,
// ported from tg2sip-webrtc) to RingRTC's raw-PCM push/pull C ABI
// (native/ringrtc/signal2sip_ringrtc.h, Milestone D/E) - no OS audio
// device, no PulseAudio, anywhere in the call-audio path. Mirrors
// tg2sip-webrtc's TgCallsController's audio-side responsibilities
// (mic_buffer_/playout_buffer_, AudioMediaInput()/AudioMediaOutput(),
// a steady 10ms feeder loop), but the loop here does BOTH directions
// itself (pop-and-push, pull-and-push) each tick, since RingRTC's raw-PCM
// ADM is pull-based (signal2sip_pull_playout_samples) rather than
// tgcalls' push/callback style (OnFrames) - there is no separate
// "OnFrames" callback to hang the RingRTC->SIP direction off of.

#ifndef SIGNAL2SIP_VOIP_RINGRTC_SIP_BRIDGE_H
#define SIGNAL2SIP_VOIP_RINGRTC_SIP_BRIDGE_H

#include <atomic>
#include <memory>
#include <thread>

#include <pjsua2.hpp>

#include "audio_bridge.h"
#include "ring_buffer.h"
#include "../ringrtc/signal2sip_ringrtc.h"

namespace voip {

    // Not thread-safe to construct/destruct while a call is using the
    // returned AudioMedia pointers - construct before the call starts,
    // destroy after it ends, same lifetime discipline as tg2sip's
    // TgCallsController.
    class RingRtcSipBridge {
    public:
        // `handle` is borrowed, not owned - the caller is responsible for
        // its lifetime (signal2sip_call_manager_create/_destroy), same as
        // this project's other RingRTC C ABI callers.
        explicit RingRtcSipBridge(Signal2sipCallManagerHandle *handle);
        ~RingRtcSipBridge();

        // Begins the 10ms feeder loop and activates both ring-buffer ports.
        // Call once the SIP call and RingRTC call are both established
        // (media flowing both ways).
        void Start();

        // Stops the feeder loop and deactivates both ports. Safe to call
        // even if Start() was never called.
        void Stop();

        pj::AudioMedia *AudioMediaInput() { return &audio_input_; }
        pj::AudioMedia *AudioMediaOutput() { return &audio_output_; }

        // For wrapping in a pjmedia_resample_port at the call site when the
        // SIP call's negotiated clock rate isn't 48kHz - see
        // SoftwareAudioInput::GetPjmediaPort()'s comment.
        pjmedia_port *InputPjmediaPort() { return audio_input_.GetPjmediaPort(); }
        pjmedia_port *OutputPjmediaPort() { return audio_output_.GetPjmediaPort(); }

        // Records the resample ports wireBridgeAudio() (main.cpp) wires
        // InputPjmediaPort()/OutputPjmediaPort() through, so the destructor
        // can tear them down BEFORE audio_input_/audio_output_ get
        // destroyed - see ~RingRtcSipBridge()'s own comment for why this
        // matters. Idempotent: a no-op if already set, since
        // onCallMediaState() (and therefore wireBridgeAudio()) can fire
        // more than once for the same call - without this guard a second
        // firing would wire up a SECOND pair of resample ports into the
        // same downstream ports (double audio delivery) and leak the
        // first pair's ids here.
        bool HasResamplePorts() const { return resample_pool_ != nullptr; }
        void SetResamplePorts(pj_pool_t *pool, pjsua_conf_port_id in_id, pjsua_conf_port_id out_id) {
            resample_pool_ = pool;
            in_resample_id_ = in_id;
            out_resample_id_ = out_id;
        }

    private:
        void FeederLoop();

        pj_pool_t *resample_pool_{nullptr};
        pjsua_conf_port_id in_resample_id_{PJSUA_INVALID_ID};
        pjsua_conf_port_id out_resample_id_{PJSUA_INVALID_ID};

        static constexpr size_t kRingBufferCapacitySamples = 48000 * 2; // 2s @ 48kHz
        static constexpr unsigned kSamplesPerFrame = 480; // 10ms @ 48kHz mono

        Signal2sipCallManagerHandle *handle_;

        std::shared_ptr<RingBuffer> mic_buffer_{std::make_shared<RingBuffer>(kRingBufferCapacitySamples)};
        std::shared_ptr<RingBuffer> playout_buffer_{std::make_shared<RingBuffer>(kRingBufferCapacitySamples)};

        SoftwareAudioInput audio_input_{mic_buffer_};
        SoftwareAudioOutput audio_output_{playout_buffer_};

        std::atomic<bool> feeder_running_{false};
        std::thread feeder_thread_;
    };

}

#endif //SIGNAL2SIP_VOIP_RINGRTC_SIP_BRIDGE_H
