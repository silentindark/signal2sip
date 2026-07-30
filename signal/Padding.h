#pragma once

#include "../storage/Storage.h"

namespace signal2sip {

// Byte-for-byte port of layer1/padding.js (itself a port of
// PushTransportDetails.java): pads plaintext to 80-byte block boundaries
// with a 0x80 terminator before encrypting, and strips it back off after
// decrypting.
Bytes padMessageBody(const Bytes& messageBody);
Bytes stripPaddingMessageBody(const Bytes& messageWithPadding);

} // namespace signal2sip
