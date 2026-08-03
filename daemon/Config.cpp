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

bool getBool(const IniMap& ini, const std::string& section, const std::string& key, bool fallback) {
    std::string value = getOr(ini, section, key, "");
    if (value.empty()) return fallback;
    return value == "yes" || value == "true" || value == "1";
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
    daemon.global.sipPort = static_cast<unsigned>(std::stoul(getOr(ini, "global", "sip_port", "5063")));

    // Zero accounts is a valid (if useless for the daemon itself) config -
    // gendb (native/gendb/) needs to load a config that has [global] but
    // not yet any [account.<name>] section, to add the very first one.
    std::vector<std::string> names = collectAccountNames(ini);

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
        account.sipSrtp = getOr(ini, section, "sip_srtp", "disabled");
        if (account.sipSrtp != "disabled" && account.sipSrtp != "optional" && account.sipSrtp != "mandatory") {
            throw std::runtime_error("signal2sip.conf: [" + section +
                                     "] sip_srtp must be disabled/optional/mandatory, got '" + account.sipSrtp + "'");
        }

        account.sipTransport = getOr(ini, section, "sip_transport", "udp");
        if (account.sipTransport != "udp" && account.sipTransport != "tls") {
            throw std::runtime_error("signal2sip.conf: [" + section + "] sip_transport must be udp/tls, got '" +
                                     account.sipTransport + "'");
        }
        // sip_host with no explicit ":port" defaults to Asterisk's plain
        // SIP port implicitly (whatever sip:'s own resolution does) - but
        // for tls, default explicitly to 5061 (Asterisk's usual TLS
        // listener port, and this project's own DPDZK test setup) rather
        // than leaving it to chance, since a bare hostname/IP here would
        // otherwise resolve however PJSIP's sips: URI handling decides on
        // its own.
        if (account.sipTransport == "tls" && !account.sipHost.empty() &&
            account.sipHost.find(':') == std::string::npos) {
            account.sipHost += ":5061";
        }
        account.sipTlsCaFile = getOr(ini, section, "sip_tls_ca_file", "");
        account.sipTlsInsecure = getBool(ini, section, "sip_tls_insecure", false);
        if (account.sipTransport == "tls" && account.sipTlsCaFile.empty() && !account.sipTlsInsecure) {
            throw std::runtime_error(
                "signal2sip.conf: [" + section +
                "] sip_transport=tls needs either sip_tls_ca_file (pin the Asterisk server's certificate) or "
                "sip_tls_insecure=yes (skip verification entirely) - one of the two is required, not silently "
                "insecure by default");
        }

        account.outgoingCallTarget = getOr(ini, section, "outgoing_call_target", "");

        daemon.accounts.push_back(std::move(account));
    }

    return daemon;
}

GlobalConfig loadGlobalConfigLenient(const std::string& path) {
    GlobalConfig global;
    if (!fileExists(path)) return global;
    IniMap ini = parseIni(path);
    global.dbPath = getOr(ini, "global", "db_path", "");
    global.dbKey = getOr(ini, "global", "db_key", "");
    return global;
}

} // namespace signal2sip
