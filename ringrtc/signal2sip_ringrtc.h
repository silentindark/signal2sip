// Hand-written header for RingRTC's Milestone E C ABI
// (~/GIT/vladonv/ringrtc/src/rust/src/cpp_ffi.rs) - kept in sync manually
// since that crate has no cbindgen setup of its own. Every function here
// is a plain #[unsafe(no_mangle)] extern "C" fn, confirmed present with
// `nm` against the built libringrtc.a.
#pragma once

#include <cstdint>

extern "C" {

struct Signal2sipCallManagerHandle;

// One Callbacks struct per call manager instance - `context` is passed
// back on every invocation (e.g. a `this` pointer for whatever owns the
// call manager). Field order/types must exactly match cpp_ffi.rs's
// `Callbacks` struct (repr(C)).
struct Signal2sipCallbacks {
    void* context;
    // (context, remote_peer_id, call_id, call_media_type, opaque, opaque_len)
    void (*send_offer)(void*, const char*, uint64_t, int32_t, const uint8_t*, size_t);
    // (context, remote_peer_id, call_id, opaque, opaque_len)
    void (*send_answer)(void*, const char*, uint64_t, const uint8_t*, size_t);
    // (context, remote_peer_id, call_id, has_receiver_device_id, receiver_device_id, opaque, opaque_len)
    void (*send_ice)(void*, const char*, uint64_t, bool, uint32_t, const uint8_t*, size_t);
    // (context, remote_peer_id, call_id, hangup_type, hangup_device_id)
    void (*send_hangup)(void*, const char*, uint64_t, int32_t, uint32_t);
    // (context, remote_peer_id, call_id, call_state) - see CALL_STATE_* below.
    void (*call_state)(void*, const char*, uint64_t, int32_t);
};

constexpr int32_t SIGNAL2SIP_CALL_STATE_INCOMING_AUDIO = 0;
constexpr int32_t SIGNAL2SIP_CALL_STATE_OUTGOING_AUDIO = 1;
constexpr int32_t SIGNAL2SIP_CALL_STATE_RINGING = 2;
constexpr int32_t SIGNAL2SIP_CALL_STATE_CONNECTED = 3;
constexpr int32_t SIGNAL2SIP_CALL_STATE_CONNECTING = 4;
constexpr int32_t SIGNAL2SIP_CALL_STATE_ENDED = 5;
constexpr int32_t SIGNAL2SIP_CALL_STATE_REJECTED = 6;
constexpr int32_t SIGNAL2SIP_CALL_STATE_CONCLUDED = 7;

// Installs a stderr logger for this library - call once before creating
// any call manager, or error!/info!/warn! diagnostics are silently dropped.
void signal2sip_init_logging();

Signal2sipCallManagerHandle* signal2sip_call_manager_create(Signal2sipCallbacks callbacks);
void signal2sip_call_manager_destroy(Signal2sipCallManagerHandle* handle);

void signal2sip_push_recorded_samples(Signal2sipCallManagerHandle* handle, const int16_t* samples,
                                       size_t num_samples);
size_t signal2sip_pull_playout_samples(Signal2sipCallManagerHandle* handle, int16_t* out,
                                        size_t max_samples);

uint64_t signal2sip_call_start_outgoing(Signal2sipCallManagerHandle* handle, const char* remote_peer_id,
                                        uint32_t local_device_id);
bool signal2sip_call_received_offer(Signal2sipCallManagerHandle* handle, const char* remote_peer_id,
                                     uint64_t call_id, uint32_t sender_device_id, uint32_t receiver_device_id,
                                     const uint8_t* opaque, size_t opaque_len);
bool signal2sip_call_accept(Signal2sipCallManagerHandle* handle, uint64_t call_id);
bool signal2sip_call_proceed(Signal2sipCallManagerHandle* handle, uint64_t call_id);
bool signal2sip_call_received_answer(Signal2sipCallManagerHandle* handle, const char* remote_peer_id,
                                      uint64_t call_id, uint32_t sender_device_id, const uint8_t* opaque,
                                      size_t opaque_len);
bool signal2sip_call_received_ice(Signal2sipCallManagerHandle* handle, const char* remote_peer_id,
                                   uint64_t call_id, uint32_t sender_device_id, const uint8_t* opaque,
                                   size_t opaque_len);
// Must be called after actually delivering each send_offer/send_answer/
// send_ice/send_hangup callback's message - RingRTC's signaling queue
// will not send the next queued message (e.g. the next ICE candidate)
// until this (or the failure variant below) is called. Missing this is
// what caused calls to gather ICE candidates on both sides but never
// exchange them, stalling in ConnectingBeforeAccepted until RingRTC's own
// ~60s CallTimeout ended the call.
bool signal2sip_call_message_sent(Signal2sipCallManagerHandle* handle, uint64_t call_id);
bool signal2sip_call_message_send_failure(Signal2sipCallManagerHandle* handle, uint64_t call_id);
bool signal2sip_call_hangup(Signal2sipCallManagerHandle* handle);

} // extern "C"
