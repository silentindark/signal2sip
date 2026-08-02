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

// Every account's own name, collected from `[account.<name>]` section
// headers.
std::vector<std::string> collectAccountNames(const IniMap& ini) {
    constexpr char kPrefix[] = "account.";
    constexpr size_t kPrefixLen = sizeof(kPrefix) - 1;
    std::vector<std::string> names;
    for (const auto& [section, _] : ini) {
        if (section.rfind(kPrefix, 0) == 0 && section.size() > kPrefixLen) {
            names.push_back(section.substr(kPrefixLen));
        }
    }
    return names;
}

} // namespace

std::string resolveConfigPath(int argc, char** argv) {
    if (argc > 1 && argv[1][0] != '\0') return argv[1];
    if (fileExists("/etc/signal2sip/signal2sip.conf")) return "/etc/signal2sip/signal2sip.conf";
    return "./signal2sip.conf";
}

DaemonConfig DaemonConfig::load(const std::string& path) {
    IniMap ini = parseIni(path);

    DaemonConfig daemon;
    daemon.global.dbPath = getOr(ini, "global", "db_path", "");
    if (daemon.global.dbPath.empty()) {
        throw std::runtime_error("signal2sip.conf: [global] db_path is required");
    }
    daemon.global.dbKey = getOr(ini, "global", "db_key", "");
    if (daemon.global.dbKey.empty()) {
        throw std::runtime_error("signal2sip.conf: [global] db_key is required");
    }

    std::vector<std::string> names = collectAccountNames(ini);
    if (names.empty()) {
        throw std::runtime_error("signal2sip.conf: no [account.<name>] sections found");
    }

    for (const std::string& name : names) {
        AccountConfig account;
        account.name = name;

        const std::string section = "account." + name;
        account.e164 = getOr(ini, section, "e164", "");
        if (account.e164.empty()) {
            throw std::runtime_error("signal2sip.conf: [" + section + "] e164 is required");
        }
        account.serverUrl = getOr(ini, section, "server_url", "");

        account.sipHost = getOr(ini, section, "sip_host", "");
        account.sipExtension = getOr(ini, section, "sip_extension", "");
        account.sipPassword = getOr(ini, section, "sip_password", "");
        account.sipBridgeDestination = getOr(ini, section, "sip_bridge_destination", "");
        account.sipPort = static_cast<unsigned>(std::stoul(getOr(ini, section, "sip_port", "5063")));

        account.outgoingCallTarget = getOr(ini, section, "outgoing_call_target", "");

        daemon.accounts.push_back(std::move(account));
    }

    return daemon;
}

} // namespace signal2sip
