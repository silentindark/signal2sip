// Milestone F: PJSIP-facing audio ports, ported from tg2sip-webrtc's
// tg2sip/voip/audio_bridge.h (same pjmedia_port-wrapped-as-pj::AudioMedia
// pattern via registerMediaPort(), same 10ms/480-sample @ 48kHz mono frame
// convention - matches this project's RingRTC raw-PCM ADM exactly, so
// neither side needs to buffer partial frames) - just reads/writes a
// RingBuffer instead of a libtgvoip/ntgcalls callback. No OS audio device
// anywhere in the call-audio path.

#ifndef SIGNAL2SIP_VOIP_AUDIO_BRIDGE_H
#define SIGNAL2SIP_VOIP_AUDIO_BRIDGE_H

#include <memory>

#include <pjsua2.hpp>

#include "ring_buffer.h"

namespace voip {

    // SIP -> RingRTC direction: PJSIP pushes decoded RTP audio in, we buffer
    // it for the feeder loop to hand to RingRTC as "microphone" input
    // (signal2sip_push_recorded_samples).
    class SoftwareAudioInput : public pj::AudioMedia {
    public:
        explicit SoftwareAudioInput(std::shared_ptr<RingBuffer> mic_buffer);

        ~SoftwareAudioInput() override;

        void Start();

        void Stop();

        // For wrapping in a pjmedia_resample_port when the SIP call's own
        // negotiated clock rate doesn't match this port's fixed 48kHz
        // (this build's PJSIP conference bridge is the non-resampling
        // "switchboard" variant - pjsua_conf_connect() between mismatched
        // rates fails outright with PJMEDIA_ENOTCOMPATIBLE, confirmed
        // live against DPDZK's *43 test, which is PCMU/8000-only).
        pjmedia_port *GetPjmediaPort() const { return media_port_; }

    private:
        static pj_status_t PutFrameCallback(pjmedia_port *port, pjmedia_frame *frame);

        static pj_status_t GetFrameCallback(pjmedia_port *port, pjmedia_frame *frame);

        std::shared_ptr<RingBuffer> mic_buffer_;
        bool active_{false};

        pj_pool_t *pj_pool_;
        pjmedia_port *media_port_;
    };

    // RingRTC -> SIP direction: the feeder loop pulls decoded call audio from
    // RingRTC (signal2sip_pull_playout_samples) and buffers it here, PJSIP
    // pulls it out to send over RTP.
    class SoftwareAudioOutput : public pj::AudioMedia {
    public:
        explicit SoftwareAudioOutput(std::shared_ptr<RingBuffer> playout_buffer);

        ~SoftwareAudioOutput() override;

        void Start();

        void Stop();

        // See SoftwareAudioInput::GetPjmediaPort().
        pjmedia_port *GetPjmediaPort() const { return media_port_; }

    private:
        static pj_status_t PutFrameCallback(pjmedia_port *port, pjmedia_frame *frame);

        static pj_status_t GetFrameCallback(pjmedia_port *port, pjmedia_frame *frame);

        std::shared_ptr<RingBuffer> playout_buffer_;
        bool active_{false};

        pj_pool_t *pj_pool_;
        pjmedia_port *media_port_;
    };

}

#endif //SIGNAL2SIP_VOIP_AUDIO_BRIDGE_H
