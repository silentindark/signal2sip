// Milestone F: lock-free SPSC ring buffer decoupling PJSIP's 10ms media
// clock thread from RingRTC's own push/pull audio calls, matching
// tg2sip-webrtc's tg2sip/voip/ring_buffer.h pattern exactly (same file,
// ported near-verbatim - proven correct in production there).

#ifndef SIGNAL2SIP_VOIP_RING_BUFFER_H
#define SIGNAL2SIP_VOIP_RING_BUFFER_H

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace voip {

    // Single-producer/single-consumer lock-free ring buffer of PCM samples.
    class RingBuffer {
    public:
        explicit RingBuffer(size_t capacity_samples)
                : capacity_(capacity_samples), buffer_(capacity_samples) {}

        // Called from the producer thread only.
        void push(const int16_t *data, size_t samples) {
            size_t head = head_.load(std::memory_order_relaxed);
            size_t tail = tail_.load(std::memory_order_acquire);

            size_t available = capacity_ - 1 - (head - tail + capacity_) % capacity_;
            if (samples > available) samples = available;
            if (samples == 0) return;

            for (size_t i = 0; i < samples; ++i) {
                buffer_[(head + i) % capacity_] = data[i];
            }
            head_.store((head + samples) % capacity_, std::memory_order_release);
        }

        // Called from the consumer thread only. Pads with silence on underrun
        // so callers always get exactly `samples` values.
        void pop(int16_t *data, size_t samples) {
            size_t head = head_.load(std::memory_order_acquire);
            size_t tail = tail_.load(std::memory_order_relaxed);

            size_t available = (head - tail + capacity_) % capacity_;

            size_t to_copy = samples < available ? samples : available;
            for (size_t i = 0; i < to_copy; ++i) {
                data[i] = buffer_[(tail + i) % capacity_];
            }
            for (size_t i = to_copy; i < samples; ++i) {
                data[i] = 0;
            }
            tail_.store((tail + to_copy) % capacity_, std::memory_order_release);
        }

    private:
        const size_t capacity_;
        std::vector<int16_t> buffer_;
        std::atomic<size_t> head_{0};
        std::atomic<size_t> tail_{0};
    };

}

#endif //SIGNAL2SIP_VOIP_RING_BUFFER_H
