#include <cassert>
#include "audio_bridge.h"

using namespace voip;

namespace {
    constexpr unsigned SAMPLES_PER_FRAME = 480; // 10ms @ 48kHz mono
}

// ---- SoftwareAudioInput (SIP -> RingRTC) ----

SoftwareAudioInput::SoftwareAudioInput(std::shared_ptr<RingBuffer> mic_buffer) : mic_buffer_(std::move(mic_buffer)) {
    pj_pool_ = pjsua_pool_create("voip-input%p", 2048, 512);
    media_port_ = PJ_POOL_ZALLOC_T(pj_pool_, pjmedia_port);

    pj_str_t name = pj_str((char *) "voip-input");
    pj_status_t status = pjmedia_port_info_init(&media_port_->info, &name,
                                                PJMEDIA_SIG_CLASS_PORT_AUD('S', 'I'), // Signal Input
                                                48000, 1, 16, SAMPLES_PER_FRAME);
    assert(status == PJ_SUCCESS);

    media_port_->port_data.pdata = this;
    media_port_->put_frame = &PutFrameCallback;
    media_port_->get_frame = &GetFrameCallback;

    registerMediaPort(media_port_);
}

SoftwareAudioInput::~SoftwareAudioInput() {
    unregisterMediaPort();
    pjmedia_port_destroy(media_port_);
    pj_pool_release(pj_pool_);
}

void SoftwareAudioInput::Start() { active_ = true; }

void SoftwareAudioInput::Stop() { active_ = false; }

pj_status_t SoftwareAudioInput::PutFrameCallback(pjmedia_port *port, pjmedia_frame *frame) {
    if (frame->type != PJMEDIA_FRAME_TYPE_AUDIO) {
        return PJ_SUCCESS;
    }

    auto *input = (SoftwareAudioInput *) port->port_data.pdata;
    if (!input->active_) {
        return PJ_SUCCESS;
    }

    input->mic_buffer_->push(static_cast<const int16_t *>(frame->buf), frame->size / sizeof(int16_t));

    return PJ_SUCCESS;
}

pj_status_t SoftwareAudioInput::GetFrameCallback(pjmedia_port *port, pjmedia_frame *frame) {
    frame->type = PJMEDIA_FRAME_TYPE_NONE;
    frame->size = 0;
    return PJ_SUCCESS;
}

// ---- SoftwareAudioOutput (RingRTC -> SIP) ----

SoftwareAudioOutput::SoftwareAudioOutput(std::shared_ptr<RingBuffer> playout_buffer) : playout_buffer_(std::move(playout_buffer)) {
    pj_pool_ = pjsua_pool_create("voip-output%p", 2048, 512);
    media_port_ = PJ_POOL_ZALLOC_T(pj_pool_, pjmedia_port);

    pj_str_t name = pj_str((char *) "voip-output");
    pj_status_t status = pjmedia_port_info_init(&media_port_->info, &name,
                                                PJMEDIA_SIG_CLASS_PORT_AUD('S', 'O'), // Signal Output
                                                48000, 1, 16, SAMPLES_PER_FRAME);
    assert(status == PJ_SUCCESS);

    media_port_->port_data.pdata = this;
    media_port_->put_frame = &PutFrameCallback;
    media_port_->get_frame = &GetFrameCallback;

    registerMediaPort(media_port_);
}

SoftwareAudioOutput::~SoftwareAudioOutput() {
    unregisterMediaPort();
    pjmedia_port_destroy(media_port_);
    pj_pool_release(pj_pool_);
}

void SoftwareAudioOutput::Start() { active_ = true; }

void SoftwareAudioOutput::Stop() { active_ = false; }

pj_status_t SoftwareAudioOutput::PutFrameCallback(pjmedia_port *port, pjmedia_frame *frame) {
    frame->type = PJMEDIA_FRAME_TYPE_NONE;
    frame->size = 0;
    return PJ_SUCCESS;
}

pj_status_t SoftwareAudioOutput::GetFrameCallback(pjmedia_port *port, pjmedia_frame *frame) {
    auto *output = (SoftwareAudioOutput *) port->port_data.pdata;

    if (!output->active_) {
        frame->type = PJMEDIA_FRAME_TYPE_NONE;
        frame->size = 0;
        return PJ_SUCCESS;
    }

    output->playout_buffer_->pop(static_cast<int16_t *>(frame->buf), SAMPLES_PER_FRAME);
    frame->type = PJMEDIA_FRAME_TYPE_AUDIO;
    frame->size = SAMPLES_PER_FRAME * sizeof(int16_t);

    return PJ_SUCCESS;
}
