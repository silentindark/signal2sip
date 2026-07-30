#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace signal2sip {

std::string base64Encode(const std::vector<uint8_t>& input);
std::vector<uint8_t> base64Decode(const std::string& input);

} // namespace signal2sip
