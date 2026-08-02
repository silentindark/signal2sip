#pragma once

// signal2sip.conf parser - minimal hand-rolled INI reader (no new
// dependency; matches this project's existing preference for small
// hand-rolled parsing over pulling in a library for something this simple
// - see AuthSocket.cpp/pjsip-gateway.cpp's own hand-rolled JSON field
// extraction). Section-and-key-value only, `;`/`#` comments.
//
// One process now serves N Signal accounts (each optionally with its own
// SIP trunk) from a single file - repeated `[signal.<name>]`/
// `[sip.<name>]`/`[other.<name>]` section groups, one group per account,
// `<name>` an arbitrary label shared across all three sections for the
// same account (this project's own convention: the e164 digits with no
// `+`, since INI section names can't safely hold arbitrary punctuation
// and this avoids inventing a separate label concept to keep in sync with
// `e164=` inside the block - not an INI syntax requirement, just this
// project's convention). Was one account/one file per process (matching
// tg2sip-webrtc's own model) - deliberately reversed since tg2sip has no
// real in-process-multi-account precedent to mirror; see the project's
// memory for that decision).
//
// argv[1] -> /etc/signal2sip/signal2sip.conf -> ./signal2sip.conf,
// matching tg2sip/utils.cpp's resolve_config_path() exactly (same
// fallback order, same rationale: works both installed via systemd and
// run from a dev checkout).

#include <string>
#include <vector>

namespace signal2sip {

std::string resolveConfigPath(int argc, char** argv);

struct AccountConfig {
    // The "<name>" in [signal.<name>]/[sip.<name>]/[other.<name>] - used
    // as this account's key everywhere in the daemon (the accounts map,
    // log-line prefixes) and to derive PJSIP transport port defaults.
    std::string name;

    // [signal.<name>]
    std::string e164;                 // required
    std::string accountDataDir = ".";  // where <e164>.db lives
    std::string dbKey;                 // SQLCipher passphrase, required
    std::string serverUrl;             // empty = production chat.signal.org

    // [sip.<name>] - entirely optional; an account with no [sip.<name>]
    // section never touches PJSIP at all (Signal-only account).
    std::string sipHost;
    std::string sipExtension;
    std::string sipPassword;
    // What to dial out to when bridging an incoming Signal call to SIP -
    // e.g. "*43" for DPDZK's echo test, or a real destination extension.
    std::string sipBridgeDestination;
    unsigned sipPort = 5063;

    // [other.<name>]
    // The other account to place a test outgoing call to, if set -
    // matches this milestone's live-verification step (a real Signal
    // call from one signal2sip-daemon account to another's ACI). Empty
    // means this account only answers incoming calls.
    std::string outgoingCallTarget;

    bool hasSip() const { return !sipHost.empty(); }
};

struct DaemonConfig {
    std::vector<AccountConfig> accounts;

    static DaemonConfig load(const std::string& path);
};

} // namespace signal2sip
