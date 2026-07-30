#include "../signal/Padding.h"

#include <iostream>
#include <string>

using namespace signal2sip;

namespace {
int g_failures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "PASS: " << what << "\n";
    } else {
        std::cout << "FAIL: " << what << "\n";
        g_failures++;
    }
}

Bytes bytesFrom(const std::string& s) {
    return Bytes(s.begin(), s.end());
}

std::string stringFrom(const Bytes& b) {
    return std::string(b.begin(), b.end());
}
} // namespace

int main() {
    // Empty message: paddedMessageLength(0+1)=80, minus 1 = 79 bytes, [0]=0x80.
    {
        Bytes padded = padMessageBody(bytesFrom(""));
        check(padded.size() == 79, "empty message pads to 79 bytes");
        check(padded[0] == 0x80, "empty message: terminator at index 0");
    }

    // Round-trip a handful of message lengths, including ones that land
    // exactly on a block boundary (the trickiest case for off-by-ones).
    for (size_t len : {0u, 1u, 5u, 78u, 79u, 80u, 81u, 159u, 160u, 161u}) {
        std::string msg(len, 'x');
        Bytes padded = padMessageBody(bytesFrom(msg));
        check(padded.size() % 80 == 79, "len=" + std::to_string(len) + ": padded size is 80k-1");
        Bytes stripped = stripPaddingMessageBody(padded);
        check(stringFrom(stripped) == msg, "len=" + std::to_string(len) + ": round-trips exactly");
    }

    // A message containing trailing 0x00 bytes itself must not be
    // truncated at the wrong spot - only the actual 0x80 terminator counts.
    {
        std::string msg = "hello";
        msg.push_back('\0');
        msg.push_back('\0');
        Bytes padded = padMessageBody(bytesFrom(msg));
        Bytes stripped = stripPaddingMessageBody(padded);
        check(stringFrom(stripped) == msg, "message with embedded trailing NULs round-trips exactly");
    }

    std::cout << "\n" << (g_failures == 0 ? "ALL PASS" : std::to_string(g_failures) + " FAILURE(S)") << "\n";
    return g_failures == 0 ? 0 : 1;
}
