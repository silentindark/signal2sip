#include "Config.h"

#include <fstream>
#include <map>
#include <stdexcept>
#include <sys/stat.h>

namespace signal2sip {

namespace {

bool fileExists(const std::string& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0;
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// section -> key -> value
using IniMap = std::map<std::string, std::map<std::string, std::string>>;

IniMap parseIni(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw std::runtime_error("cannot open config file: " + path);

    IniMap result;
    std::string section;
    std::string line;
    while (std::getline(f, line)) {
        std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed[0] == ';' || trimmed[0] == '#') continue;
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            section = trimmed.substr(1, trimmed.size() - 2);
            continue;
        }
        size_t eq = trimmed.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(trimmed.substr(0, eq));
        std::string value = trim(trimmed.substr(eq + 1));
        result[section][key] = value;
    }
    return result;
}

std::string getOr(const IniMap& ini, const std::string& section, const std::string& key,
                   const std::string& fallback) {
    auto sec = ini.find(section);
    if (sec == ini.end()) return fallback;
    auto it = sec->second.find(key);
    if (it == sec->second.end() || it->second.empty()) return fallback;
    return it->second;
}

} // namespace

std::string resolveConfigPath(int argc, char** argv) {
    if (argc > 1 && argv[1][0] != '\0') return argv[1];
    if (fileExists("/etc/signal2sip/signal2sip.conf")) return "/etc/signal2sip/signal2sip.conf";
    return "./signal2sip.conf";
}

Config Config::load(const std::string& path) {
    IniMap ini = parseIni(path);

    Config config;
    config.e164 = getOr(ini, "signal", "e164", "");
    if (config.e164.empty()) throw std::runtime_error("signal2sip.conf: [signal] e164 is required");
    config.accountDataDir = getOr(ini, "signal", "account_data_dir", ".");
    config.dbKey = getOr(ini, "signal", "db_key", "");
    if (config.dbKey.empty()) throw std::runtime_error("signal2sip.conf: [signal] db_key is required");
    config.serverUrl = getOr(ini, "signal", "server_url", "");

    config.sipHost = getOr(ini, "sip", "host", "");
    config.sipExtension = getOr(ini, "sip", "extension", "");
    config.sipPassword = getOr(ini, "sip", "password", "");
    config.sipBridgeDestination = getOr(ini, "sip", "bridge_destination", "");
    config.sipPort = static_cast<unsigned>(std::stoul(getOr(ini, "sip", "port", "5063")));

    config.outgoingCallTarget = getOr(ini, "other", "outgoing_call_target", "");

    return config;
}

} // namespace signal2sip
