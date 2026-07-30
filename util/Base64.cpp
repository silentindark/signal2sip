#include "Base64.h"

#include <array>

namespace signal2sip {

std::string base64Encode(const std::vector<uint8_t>& input) {
    static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((input.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= input.size()) {
        uint32_t n = (static_cast<uint32_t>(input[i]) << 16) | (static_cast<uint32_t>(input[i + 1]) << 8) |
                     static_cast<uint32_t>(input[i + 2]);
        out.push_back(kAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kAlphabet[(n >> 12) & 0x3F]);
        out.push_back(kAlphabet[(n >> 6) & 0x3F]);
        out.push_back(kAlphabet[n & 0x3F]);
        i += 3;
    }
    size_t remaining = input.size() - i;
    if (remaining == 1) {
        uint32_t n = static_cast<uint32_t>(input[i]) << 16;
        out.push_back(kAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kAlphabet[(n >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (remaining == 2) {
        uint32_t n = (static_cast<uint32_t>(input[i]) << 16) | (static_cast<uint32_t>(input[i + 1]) << 8);
        out.push_back(kAlphabet[(n >> 18) & 0x3F]);
        out.push_back(kAlphabet[(n >> 12) & 0x3F]);
        out.push_back(kAlphabet[(n >> 6) & 0x3F]);
        out.push_back('=');
    }
    return out;
}

std::vector<uint8_t> base64Decode(const std::string& input) {
    static const auto kTable = [] {
        std::array<int8_t, 256> table{};
        table.fill(-1);
        const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; i++) table[static_cast<uint8_t>(alphabet[i])] = static_cast<int8_t>(i);
        return table;
    }();

    std::vector<uint8_t> out;
    out.reserve((input.size() / 4) * 3);
    uint32_t buffer = 0;
    int bits = 0;
    for (char c : input) {
        if (c == '=') break;
        int8_t value = kTable[static_cast<uint8_t>(c)];
        if (value < 0) continue;
        buffer = (buffer << 6) | static_cast<uint32_t>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xFF));
        }
    }
    return out;
}

} // namespace signal2sip
