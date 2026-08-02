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

// Every account's own name, collected from `[signal.<name>]` section
// headers specifically - `[sip.<name>]`/`[other.<name>]` are looked up
// per-name below but never define an account on their own (a `[sip.*]`
// section with no matching `[signal.*]` is just ignored, same as any
// other unrecognized section - `parseIni()` itself is already fully
// permissive about unknown sections).
std::vector<std::string> collectAccountNames(const IniMap& ini) {
    constexpr char kPrefix[] = "signal.";
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
    std::vector<std::string> names = collectAccountNames(ini);
    if (names.empty()) {
        throw std::runtime_error("signal2sip.conf: no [signal.<name>] sections found");
    }

    DaemonConfig daemon;
    for (const std::string& name : names) {
        AccountConfig account;
        account.name = name;

        const std::string signalSection = "signal." + name;
        account.e164 = getOr(ini, signalSection, "e164", "");
        if (account.e164.empty()) {
            throw std::runtime_error("signal2sip.conf: [" + signalSection + "] e164 is required");
        }
        account.accountDataDir = getOr(ini, signalSection, "account_data_dir", ".");
        account.dbKey = getOr(ini, signalSection, "db_key", "");
        if (account.dbKey.empty()) {
            throw std::runtime_error("signal2sip.conf: [" + signalSection + "] db_key is required");
        }
        account.serverUrl = getOr(ini, signalSection, "server_url", "");

        const std::string sipSection = "sip." + name;
        account.sipHost = getOr(ini, sipSection, "host", "");
        account.sipExtension = getOr(ini, sipSection, "extension", "");
        account.sipPassword = getOr(ini, sipSection, "password", "");
        account.sipBridgeDestination = getOr(ini, sipSection, "bridge_destination", "");
        account.sipPort = static_cast<unsigned>(std::stoul(getOr(ini, sipSection, "port", "5063")));

        const std::string otherSection = "other." + name;
        account.outgoingCallTarget = getOr(ini, otherSection, "outgoing_call_target", "");

        daemon.accounts.push_back(std::move(account));
    }

    return daemon;
}

} // namespace signal2sip
