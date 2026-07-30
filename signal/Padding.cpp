#include "Padding.h"

#include <algorithm>

namespace signal2sip {

namespace {

constexpr size_t kPaddingBlockSize = 80;

size_t paddedMessageLength(size_t messageLength) {
    size_t messageLengthWithTerminator = messageLength + 1;
    size_t messagePartCount = messageLengthWithTerminator / kPaddingBlockSize;
    if (messageLengthWithTerminator % kPaddingBlockSize != 0) {
        messagePartCount++;
    }
    return messagePartCount * kPaddingBlockSize;
}

} // namespace

Bytes padMessageBody(const Bytes& messageBody) {
    // The +1 -1 mirrors PushTransportDetails.java's comment: leaves room for
    // the cipher to add exactly one padding byte itself, rather than a full
    // extra 16-byte block.
    Bytes padded(paddedMessageLength(messageBody.size() + 1) - 1, 0);
    std::copy(messageBody.begin(), messageBody.end(), padded.begin());
    padded[messageBody.size()] = 0x80;
    return padded;
}

Bytes stripPaddingMessageBody(const Bytes& messageWithPadding) {
    for (size_t i = messageWithPadding.size(); i-- > 0;) {
        if (messageWithPadding[i] == 0x80) {
            return Bytes(messageWithPadding.begin(), messageWithPadding.begin() + i);
        }
        if (messageWithPadding[i] != 0x00) {
            return messageWithPadding;
        }
    }
    return messageWithPadding;
}

} // namespace signal2sip
