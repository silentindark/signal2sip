#pragma once

// Milestone G: signal2sip.conf parser - minimal hand-rolled INI reader
// (no new dependency; matches this project's existing preference for
// small hand-rolled parsing over pulling in a library for something this
// simple - see AuthSocket.cpp/pjsip-gateway.cpp's own hand-rolled JSON
// field extraction). Section-and-key-value only, `;`/`#` comments,
// matches the shape in /home/vlad/.claude/plans/jiggly-mapping-plum.md's
// "Config file" section (itself mirroring tg2sip.conf).
//
// argv[1] -> /etc/signal2sip/signal2sip.conf -> ./signal2sip.conf,
// matching tg2sip/utils.cpp's resolve_config_path() exactly (same
// fallback order, same rationale: works both installed via systemd and
// run from a dev checkout).

#include <optional>
#include <string>

namespace signal2sip {

std::string resolveConfigPath(int argc, char** argv);

struct Config {
    // [signal]
    std::string e164;                 // required
    std::string accountDataDir = ".";  // where <e164>.db lives
    std::string dbKey;                 // SQLCipher passphrase, required
    std::string serverUrl;             // empty = production chat.signal.org

    // [sip]
    std::string sipHost;
    std::string sipExtension;
    std::string sipPassword;
    // What to dial out to when bridging an incoming Signal call to SIP -
    // e.g. "*43" for DPDZK's echo test, or a real destination extension.
    std::string sipBridgeDestination;
    unsigned sipPort = 5063;

    // [other]
    // The other account to place a test outgoing call to, if set -
    // matches this milestone's live-verification step (a real Signal
    // call from one signal2sip-daemon to another's ACI). Empty means
    // this instance only answers incoming calls.
    std::string outgoingCallTarget;

    static Config load(const std::string& path);
};

} // namespace signal2sip
