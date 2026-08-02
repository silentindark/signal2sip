#pragma once

// signal2sip.conf parser - minimal hand-rolled INI reader (no new
// dependency; matches this project's existing preference for small
// hand-rolled parsing over pulling in a library for something this simple
// - see AuthSocket.cpp/pjsip-gateway.cpp's own hand-rolled JSON field
// extraction). Section-and-key-value only, `;`/`#` comments.
//
// One process now serves N Signal accounts (each optionally with its own
// SIP trunk) from a single file, all sharing one database (see
// GlobalConfig/Storage's own doc comments) - one `[global]` section plus
// a repeated `[account.<name>]` section per account.
//
// `<name>` is a purely arbitrary label you choose - any string valid in
// an INI section header (letters/digits/hyphen/underscore, no spaces or
// brackets). It carries no meaning to Signal or SIP; the daemon only uses
// it as (1) this account's key in its internal accounts map, (2) the
// prefix on every log line for this account (`[daemon][<name>] ...`),
// (3) the `account_name` column value scoping this account's rows in the
// shared database. The account's real identity is `e164=`/its derived
// ACI, not `<name>` - so `[account.support-line]`, `[account.alice]`, and
// `[account.123456789004]` are all equally valid, and don't need to
// relate to the phone number at all. (Historically this project used the
// e164 digits with no `+` as the label, purely as a convention when this
// was the only naming idea around - not a requirement, and no longer
// even the example used in this project's own test configs, which now
// prefer names like `caller`/`listener` describing each account's role
// instead.)
//
// Was one account/one file per process (matching tg2sip-webrtc's own
// model) - deliberately reversed since tg2sip has no real
// in-process-multi-account precedent to mirror; see the project's memory
// for that decision.
//
// argv[1] -> /etc/signal2sip/signal2sip.conf -> ./signal2sip.conf,
// matching tg2sip/utils.cpp's resolve_config_path() exactly (same
// fallback order, same rationale: works both installed via systemd and
// run from a dev checkout).

#include <string>
#include <vector>

namespace signal2sip {

std::string resolveConfigPath(int argc, char** argv);

// [global] - one per file, shared by every account.
struct GlobalConfig {
    std::string dbPath;  // required - one SQLCipher file shared by all accounts
    std::string dbKey;   // required - SQLCipher passphrase
};

struct AccountConfig {
    // The "<name>" in [account.<name>] - used as this account's key
    // everywhere in the daemon (the accounts map, log-line prefixes,
    // Storage's account_name scoping) and to derive PJSIP transport port
    // defaults.
    std::string name;

    // The account's REAL identity, not a label - the actual phone number
    // this Signal account is registered/linked under, in E.164 format
    // (leading '+', country code, e.g. "+123456789004"). Unlike `name`
    // above (an arbitrary label you pick), this value has no freedom:
    // Signal's own servers identify the account by this number (and its
    // derived ACI), so it must be the account's genuine registered
    // number, not a made-up placeholder.
    std::string e164;       // required
    std::string serverUrl;  // empty = production chat.signal.org

    // Entirely optional; an account with no sip_host never touches PJSIP
    // at all (Signal-only account).
    std::string sipHost;
    std::string sipExtension;
    std::string sipPassword;
    // What to dial out to when bridging an incoming Signal call to SIP -
    // e.g. "*43" for DPDZK's echo test, or a real destination extension.
    std::string sipBridgeDestination;
    unsigned sipPort = 5063;

    // The other account to place a test outgoing call to, if set - must
    // be the target's ACI/UUID, not its e164 (GET /v2/keys/{e164}/* 404s
    // on the current Signal server; own ACI is logged at startup).
    // Matches this milestone's live-verification step (a real Signal call
    // from one signal2sip-daemon account to another's ACI). Empty means
    // this account only answers incoming calls.
    std::string outgoingCallTarget;

    bool hasSip() const { return !sipHost.empty(); }
};

struct DaemonConfig {
    GlobalConfig global;
    std::vector<AccountConfig> accounts;

    static DaemonConfig load(const std::string& path);
};

} // namespace signal2sip
