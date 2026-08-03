#pragma once

// signal2sip.conf parser - minimal hand-rolled INI reader (no new
// dependency; matches this project's existing preference for small
// hand-rolled parsing over pulling in a library for something this simple
// - see AuthSocket.cpp/pjsip-gateway.cpp's own hand-rolled JSON field
// extraction). Section-and-key-value only, `;`/`#` comments - but ONLY as
// their own whole line. There is no inline/trailing-comment support: a
// line like `sip_extension=foo # my trunk` puts the literal text
// `foo # my trunk` (space, `#`, and all) into the value - found live as
// the actual cause of a PJSIP_EINVALIDURI failure (a commented-out
// annotation left on the same line as a real sip_extension= value). Put
// comments on their own line above the setting they refer to instead.
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

    // Local port for the daemon's own shared PJSIP UDP transport (see
    // main.cpp's g_ep doc comment) - one transport for the whole process,
    // used by every SIP-enabled account's registration, like a softphone
    // with several lines on one local port. NOT the port Asterisk listens
    // on (that's whatever [account.<name>]'s sip_host already says, e.g.
    // "192.168.16.81:5061" if non-default). Genuinely process-wide, not
    // per-account - was mistakenly a per-[account.<name>] field before
    // 08-03; only the first SIP-enabled account's value ever took effect
    // in practice, which is why it moved here.
    unsigned sipPort = 5063;
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

    // Secure media transport (SDES-SRTP) for the RTP leg to Asterisk -
    // NOT the Signal-side call encryption (already independently handled
    // by RingRTC/libsignal regardless of this setting); purely about the
    // local PJSIP<->Asterisk hop. One of "disabled" (default - plain RTP,
    // this project's behavior before 08-03), "optional" (offers SRTP,
    // PJSIP falls back to plain RTP if the Asterisk endpoint doesn't have
    // media_encryption=sdes configured - safe to turn on unilaterally,
    // won't break an unprepared trunk), or "mandatory" (refuses plain RTP
    // - only enable once the Asterisk side is confirmed to negotiate SRTP,
    // or registration/calls on this account stop working). Verified live
    // 08-03 against DPDZK: real tone round-tripped with mandatory SRTP
    // negotiated (RTP/SAVP, AES_CM_128_HMAC_SHA1_80). By itself, the SDES
    // key exchange travels in the SDP over whatever SIP transport this
    // account uses (see sipTransport below) - over plain UDP that's in
    // the clear, protecting only against something that can see RTP but
    // not SIP signaling; pair with sip_transport=tls for the signaling to
    // be protected too.
    std::string sipSrtp = "disabled"; // "disabled" | "optional" | "mandatory"

    // SIP signaling transport to Asterisk for THIS account - "udp"
    // (default, current behavior) or "tls" (SIPS - idUri/registrarUri get
    // the sips: scheme instead of sip:). Unlike sipPort's shared UDP
    // transport, each tls account gets its OWN dedicated TLS transport
    // (see main.cpp's createAccountTlsTransport()) - PJSIP's TLS trust
    // settings (CaListFile/verifyServer) are configured once per transport
    // factory and apply to every connection made through it, so two
    // accounts pointing at two different Asterisk hosts with two
    // different (self-signed) certificates genuinely need separate
    // transports, not one shared one. If sip_host has no explicit
    // ":port", tls defaults it to ":5061" (Asterisk's usual TLS listener
    // port) - see Config.cpp.
    std::string sipTransport = "udp"; // "udp" | "tls"

    // Only meaningful when sipTransport == "tls". Path to a PEM file
    // listing the certificate(s) to trust for THIS account's dedicated
    // TLS transport - pinning (trust exactly this certificate, not a real
    // CA bundle) is the right model for the common case of an internal
    // Asterisk box with a self-signed cert. Per-account, not [global],
    // because different accounts can legitimately point at different
    // Asterisk hosts with different certificates. Required unless
    // sipTlsInsecure is set instead.
    std::string sipTlsCaFile;

    // Explicit, loud opt-in to skip TLS server certificate verification
    // entirely for this account's TLS transport (the channel is still
    // encrypted - passive eavesdropping is still defeated - but the
    // server's identity isn't checked, so this doesn't protect against
    // interception by something that can also redirect/intercept the
    // connection on this network). Only takes effect if sipTlsCaFile is
    // empty; pinning wins if both are set. Default false - sip_transport=
    // tls with neither this nor sipTlsCaFile set is a config error (see
    // Config.cpp), not a silent insecure default.
    bool sipTlsInsecure = false;

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

// Reads only [global] db_path/db_key from `path`, tolerating a missing
// file or missing/empty fields (returns them as "" instead of throwing) -
// unlike DaemonConfig::load()'s validation, which signal2sip-daemon itself
// needs. Used by gendb (native/gendb/main.cpp) to detect what's missing
// before bootstrapping a brand-new [global] section on first run.
GlobalConfig loadGlobalConfigLenient(const std::string& path);

} // namespace signal2sip
