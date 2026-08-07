// signal2sip-gendb: standalone companion CLI for creating a brand-new
// Signal account - either Flow A (standalone SMS/voice registration) or
// Flow B (linking as a secondary device via QR) - mirrors tg2sip's
// gen_db.cpp (a companion binary doing the one-time interactive account
// setup the daemon itself never does, gated by the same "does the DB
// already have an account" check tg2sip's ConditionPathExists= expresses
// at the systemd level). C++ port of layer1/register-*.js and
// layer1/link-new-device.js, writing straight into the shared SQLCipher
// database signal2sip-daemon itself reads.
//
// Config file resolution matches signal2sip-daemon's own
// resolveConfigPath() exactly: --config <path>, else
// /etc/signal2sip/signal2sip.conf, else ./signal2sip.conf. Its
// [global] section (db_path/db_key) is bootstrapped automatically on a
// clean first run (missing file, or missing/empty db_path/db_key with no
// database file sitting at db_path yet) - see bootstrapGlobalConfigIfNeeded()
// below; a fresh db_key is only ever invented when there is provably no
// pre-existing encrypted database it could otherwise belong to. Its
// [account.<name>] section does NOT need to exist yet either:
// `register`/`link` can target a brand-new name, and on success gendb
// appends the matching [account.<name>] e164=... section to the config
// file itself - the one shared config signal2sip-daemon reads for every
// account never needs hand-editing for any of this.
//
// Usage:
//   signal2sip-gendb <account-name> register --e164 <e164> [sms|voice] [--config <path>]
//   signal2sip-gendb <account-name> register-captcha <token> [--config <path>]
//   signal2sip-gendb <account-name> verify <code> [--config <path>]
//   signal2sip-gendb <account-name> link [--config <path>]

#include <curl/curl.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "AccountFinisher.h"
#include "ProvisioningClient.h"
#include "../daemon/Config.h"
#include "../signal/FfiUtil.h"
#include "../storage/Storage.h"
#include "../util/Base64.h"
#include "../util/RegistrationClient.h"

using namespace signal2sip;
using json = nlohmann::json;

namespace {

// Same CA cert every native TLS client in this project pins.
constexpr const char* kCaCertPath = "/home/vlad/GIT/vladonv/signal2sip/layer1/certs/signal-root-ca.pem";

std::string base64NoPadding(const Bytes& data) {
    std::string s = base64Encode(data);
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

Bytes randomBytes(size_t n) {
    Bytes out(n);
    if (RAND_bytes(out.data(), static_cast<int>(n)) != 1) throw std::runtime_error("RAND_bytes failed");
    return out;
}

std::string dirName(const std::string& path) {
    auto pos = path.find_last_of('/');
    return pos == std::string::npos ? std::string(".") : path.substr(0, pos);
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Tolerates the common ways a captcha token gets mangled when
// copy-pasted out of a browser's address bar/failed-navigation dialog:
// surrounding whitespace (a stray trailing newline is especially common
// from a terminal paste), the whole thing wrapped in quotes (some
// terminals/dialogs include them when you copy a URL), and either the
// full `signalcaptcha://<token>` redirect URL or just the bare token
// after it - both are accepted as-is.
std::string cleanCaptchaToken(std::string token) {
    token = trim(token);
    if (token.size() >= 2 && ((token.front() == '"' && token.back() == '"') ||
                              (token.front() == '\'' && token.back() == '\''))) {
        token = token.substr(1, token.size() - 2);
    }
    token = trim(token);
    const std::string prefix = "signalcaptcha://";
    if (token.rfind(prefix, 0) == 0) token = token.substr(prefix.size());
    while (!token.empty() && token.back() == '/') token.pop_back();
    return token;
}

// Session continuity between `register`/`register-captcha`/`verify`
// invocations (a captcha or SMS delay can separate them) - a small JSON
// file next to the shared DB, mirroring registrationSession.js's
// savePending/loadPending. Transient, pre-account state - not a schema
// change.
std::string pendingFilePath(const GlobalConfig& global, const std::string& accountName) {
    return dirName(global.dbPath) + "/." + accountName + ".gendb-pending.json";
}

struct PendingRegistration {
    std::string e164;
    std::string sessionId;
    std::string password;
    std::string transport;
};

void savePending(const GlobalConfig& global, const std::string& accountName, const PendingRegistration& p) {
    json j = {{"e164", p.e164}, {"sessionId", p.sessionId}, {"password", p.password}, {"transport", p.transport}};
    std::ofstream f(pendingFilePath(global, accountName));
    if (!f) throw std::runtime_error("cannot write pending-registration file");
    f << j.dump(2);
}

PendingRegistration loadPending(const GlobalConfig& global, const std::string& accountName) {
    std::ifstream f(pendingFilePath(global, accountName));
    if (!f) {
        throw std::runtime_error("no pending registration for account '" + accountName + "' - run 'register' first");
    }
    json j;
    f >> j;
    return PendingRegistration{j.at("e164").get<std::string>(), j.at("sessionId").get<std::string>(),
                               j.at("password").get<std::string>(), j.at("transport").get<std::string>()};
}

void deletePending(const GlobalConfig& global, const std::string& accountName) {
    std::remove(pendingFilePath(global, accountName).c_str());
}

// Matches Config.h's resolveConfigPath(argc, argv) fallback chain
// (--config override, else /etc/signal2sip/signal2sip.conf, else
// ./signal2sip.conf) without duplicating its file-exists logic.
std::string resolveGendbConfigPath(const std::string& explicitPath) {
    char prog[] = "signal2sip-gendb";
    if (!explicitPath.empty()) {
        char* argvOverride[2] = {prog, const_cast<char*>(explicitPath.c_str())};
        return resolveConfigPath(2, argvOverride);
    }
    char* argvDefault[1] = {prog};
    return resolveConfigPath(1, argvDefault);
}

constexpr const char* kDefaultDbPath = "/var/lib/signal2sip/signal2sip.db";

// Fills in a missing/incomplete [global] section on a clean first run -
// bootstraps db_path (default kDefaultDbPath) and/or a freshly generated
// db_key. Only ever invents db_key when there is provably no pre-existing
// database file at db_path yet - otherwise there'd be no way to know a
// fresh random passphrase actually opens whatever's really there, so it
// refuses instead and tells the user to set the real db_key by hand.
// Purely additive to the config file, like appendAccountSection() below -
// never rewrites/touches an already-present db_path/db_key value.
void bootstrapGlobalConfigIfNeeded(const std::string& configPath) {
    GlobalConfig existing = loadGlobalConfigLenient(configPath);
    bool dbPathMissing = existing.dbPath.empty();
    bool dbKeyMissing = existing.dbKey.empty();
    if (!dbPathMissing && !dbKeyMissing) return; // already fully configured

    std::string dbPath = dbPathMissing ? kDefaultDbPath : existing.dbPath;

    if (dbKeyMissing && std::filesystem::exists(dbPath)) {
        throw std::runtime_error("[global] db_key is missing in " + configPath + " but " + dbPath +
                                 " already exists - refusing to invent a new passphrase for a database that "
                                 "might already hold real data; set the correct db_key by hand instead");
    }

    std::error_code ec;
    std::filesystem::create_directories(dirName(configPath), ec); // best-effort; the ofstream below reports failure

    std::ofstream f(configPath, std::ios::app);
    if (!f) throw std::runtime_error("cannot write to config file: " + configPath);

    std::string generatedKey;
    f << "\n[global]\n";
    if (dbPathMissing) f << "db_path=" << dbPath << "\n";
    if (dbKeyMissing) {
        generatedKey = base64NoPadding(randomBytes(32));
        f << "db_key=" << generatedKey << "\n";
    }
    f.close();

    std::cout << "[gendb] bootstrapped [global] in " << configPath << ":\n";
    if (dbPathMissing) std::cout << "  db_path=" << dbPath << "\n";
    if (dbKeyMissing) {
        std::cout << "  db_key=" << generatedKey << "\n";
        std::cout << "[gendb] IMPORTANT: back up this passphrase now (e.g. in a password manager) - it encrypts "
                     "every account's Signal keys in this database; losing it means losing every account's "
                     "identity/session state permanently, with no way to recover it.\n";
    }
}

struct ResolvedAccount {
    AccountConfig account;
    bool existedInConfig = false;
};

ResolvedAccount resolveAccount(const DaemonConfig& config, const std::string& name) {
    for (const auto& a : config.accounts) {
        if (a.name == name) return ResolvedAccount{a, true};
    }
    AccountConfig fresh;
    fresh.name = name;
    return ResolvedAccount{fresh, false};
}

// Appends a brand-new [account.<name>] section to the config file on
// disk - only called after a `verify`/`link` that just created a real
// account for a name the loaded config didn't have a section for yet.
// Purely additive (never touches existing sections/comments/formatting),
// matching how SIGHUP hot-reload already expects [account.<name>]
// sections to come and go across edits to this same file.
void appendAccountSection(const std::string& configPath, const std::string& name, const std::string& e164) {
    std::ofstream f(configPath, std::ios::app);
    if (!f) throw std::runtime_error("cannot append to config file: " + configPath);
    f << "\n[account." << name << "]\n";
    f << "e164=" << e164 << "\n";
}

void requireNoExistingAccount(Storage& storage, const std::string& name) {
    if (storage.hasAccount()) {
        throw std::runtime_error("account '" + name +
                                  "' already has a saved account in the database - use a different "
                                  "[account.<name>] section for a new number");
    }
}

std::string serverHostFor(const AccountConfig& account) {
    return account.serverUrl.empty() ? "chat.signal.org" : account.serverUrl;
}

// Guards against registering/linking a real phone number that's already
// configured under a DIFFERENT [account.<name>] section in this same
// config - unlike an account-name collision (checked via
// requireNoExistingAccount()'s hasAccount() lookup), nothing else stops
// this: the real Signal server has no idea about our local names, and
// completing a second registration/link for a number some other account
// here already owns would re-register that number on the real server,
// most likely knocking the existing device off it.
void requireE164NotUsedByOtherAccount(const DaemonConfig& config, const std::string& accountName,
                                      const std::string& e164) {
    for (const auto& a : config.accounts) {
        if (a.name != accountName && a.e164 == e164) {
            throw std::runtime_error("e164 " + e164 + " is already configured under a different account ('" +
                                     a.name +
                                     "') in this config - registering/linking it again here would re-register "
                                     "that number on the real Signal server, likely kicking the existing device "
                                     "off it");
        }
    }
}

json capabilitiesJson() {
    // requireForNewDevices=true fields (spqr, usernameChangeSyncMessage)
    // plus the rest declared false for a brand-new account/device - see
    // link-new-device.js's own comment on DeviceCapability.
    return json{{"storage", false},
               {"versionedExpirationTimer", false},
               {"attachmentBackfill", false},
               {"spqr", true},
               {"usernameChangeSyncMessage", true}};
}

json signedPreKeyJson(const GeneratedSignedPreKey& key) {
    return json{{"keyId", key.wire.keyId},
               {"publicKey", base64NoPadding(key.wire.publicKey)},
               {"signature", base64NoPadding(key.wire.signature)}};
}

json kyberPreKeyJson(const GeneratedKyberPreKey& key) {
    return json{{"keyId", key.wire.keyId},
               {"publicKey", base64NoPadding(key.wire.publicKey)},
               {"signature", base64NoPadding(key.wire.signature)}};
}

// ---- Flow A: standalone SMS/voice registration ----

void cmdRegister(const DaemonConfig& config, const std::string& accountName, const std::string& e164Arg,
                 const std::string& transport) {
    if (transport != "sms" && transport != "voice") {
        throw std::runtime_error("transport must be \"sms\" or \"voice\"");
    }
    ResolvedAccount resolved = resolveAccount(config, accountName);
    AccountConfig account = resolved.account;
    if (!resolved.existedInConfig) {
        if (e164Arg.empty()) {
            throw std::runtime_error("account '" + accountName +
                                     "' is not in the config yet - pass --e164 <e164> to register it");
        }
        account.e164 = e164Arg;
    } else if (!e164Arg.empty() && e164Arg != account.e164) {
        throw std::runtime_error("account '" + accountName + "' is already configured with e164=" + account.e164 +
                                 " - --e164 " + e164Arg + " does not match");
    }
    requireE164NotUsedByOtherAccount(config, account.name, account.e164);

    Storage storage(config.global.dbPath, config.global.dbKey, account.name);
    requireNoExistingAccount(storage, account.name);

    RegistrationClient client(serverHostFor(account));

    std::cout << "[register] creating verification session for " << account.e164 << "\n";
    json sessionBody = {{"number", account.e164}, {"pushToken", nullptr}, {"mcc", nullptr}, {"mnc", nullptr}};
    HttpResponse sessionResp = client.request("POST", "/v1/verification/session", sessionBody.dump());
    std::cout << "[register] session response: " << sessionResp.status << " " << sessionResp.body << "\n";
    if (sessionResp.status != 200) {
        std::cout << "[register] FAIL: could not create session\n";
        return;
    }

    json session = json::parse(sessionResp.body);
    std::string sessionId = session.at("id").get<std::string>();
    std::vector<std::string> requestedInformation;
    if (session.contains("requestedInformation")) {
        for (auto& v : session.at("requestedInformation")) requestedInformation.push_back(v.get<std::string>());
    }
    bool allowedToRequestCode = session.value("allowedToRequestCode", false);
    std::string ourPassword = base64NoPadding(randomBytes(18));

    // Saved right away, even if we can't request a code yet -
    // register-captcha needs this sessionId to resume instead of starting
    // a brand new session.
    savePending(config.global, account.name, PendingRegistration{account.e164, sessionId, ourPassword, transport});

    bool needsCaptcha = std::find(requestedInformation.begin(), requestedInformation.end(), "captcha") !=
                       requestedInformation.end();
    if (needsCaptcha) {
        std::cout << "[register] BLOCKED: server requires a captcha (requestedInformation includes \"captcha\").\n";
        std::cout << "[register] Open this in a real browser and solve it:\n";
        std::cout << "  https://signalcaptchas.org/registration/generate.html\n";
        std::cout << "[register] It will try to redirect to signalcaptcha://<token> - that redirect will fail\n";
        std::cout << "[register] in a normal browser, but the token should still be visible. Then run:\n";
        std::cout << "  signal2sip-gendb " << account.name << " register-captcha <token>\n";
        return;
    }
    bool needsPushChallenge = std::find(requestedInformation.begin(), requestedInformation.end(), "pushChallenge") !=
                             requestedInformation.end();
    if (needsPushChallenge) {
        std::cout << "[register] FAIL: server requires a push challenge (no push token available headlessly).\n";
        return;
    }
    if (!allowedToRequestCode) {
        std::cout << "[register] FAIL: server says allowedToRequestCode=false, cannot proceed.\n";
        return;
    }

    std::cout << "[register] requesting " << transport << " verification code...\n";
    json codeBody = {{"transport", transport}, {"client", "signal2sip"}};
    HttpResponse codeResp =
        client.request("POST", "/v1/verification/session/" + sessionId + "/code", codeBody.dump());
    std::cout << "[register] code request response: " << codeResp.status << " " << codeResp.body << "\n";
    if (codeResp.status != 200) {
        std::cout << "[register] FAIL: could not request verification code\n";
        return;
    }

    std::cout << "[register] PASS: code requested via " << transport << " - once received, run:\n";
    std::cout << "  signal2sip-gendb " << account.name << " verify <code>\n";
}

void cmdRegisterCaptcha(const DaemonConfig& config, const std::string& accountName, std::string token) {
    token = cleanCaptchaToken(token);
    if (token.empty()) throw std::runtime_error("captcha token is empty after cleanup");

    ResolvedAccount resolved = resolveAccount(config, accountName);
    PendingRegistration pending = loadPending(config.global, accountName);
    RegistrationClient client(serverHostFor(resolved.account));

    std::cout << "[captcha] submitting captcha token for session " << pending.sessionId << "\n";
    json patchBody = {
        {"captcha", token}, {"pushToken", nullptr}, {"pushChallenge", nullptr}, {"mcc", nullptr}, {"mnc", nullptr}};
    HttpResponse patchResp =
        client.request("PATCH", "/v1/verification/session/" + pending.sessionId, patchBody.dump());
    std::cout << "[captcha] response: " << patchResp.status << " " << patchResp.body << "\n";
    if (patchResp.status != 200) {
        std::cout << "[captcha] FAIL: captcha rejected\n";
        return;
    }

    json session = json::parse(patchResp.body);
    if (!session.value("allowedToRequestCode", false)) {
        std::cout << "[captcha] FAIL: still not allowed to request a code after captcha\n";
        return;
    }

    std::cout << "[captcha] captcha accepted, requesting " << pending.transport << " verification code...\n";
    json codeBody = {{"transport", pending.transport}, {"client", "signal2sip"}};
    HttpResponse codeResp =
        client.request("POST", "/v1/verification/session/" + pending.sessionId + "/code", codeBody.dump());
    std::cout << "[captcha] code request response: " << codeResp.status << " " << codeResp.body << "\n";
    if (codeResp.status != 200) {
        std::cout << "[captcha] FAIL: could not request verification code\n";
        return;
    }

    std::cout << "[captcha] PASS: code requested via " << pending.transport << " - once received, run:\n";
    std::cout << "  signal2sip-gendb " << accountName << " verify <code>\n";
}

void cmdVerify(const DaemonConfig& config, const std::string& configPath, const std::string& accountName,
              const std::string& code) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    requireNoExistingAccount(storage, accountName);

    ResolvedAccount resolved = resolveAccount(config, accountName);
    PendingRegistration pending = loadPending(config.global, accountName);
    AccountConfig account = resolved.account;
    // Not yet in the config (the common case - `register` only needed
    // --e164 once, already recorded in the pending file).
    if (account.e164.empty()) account.e164 = pending.e164;
    requireE164NotUsedByOtherAccount(config, accountName, account.e164);

    RegistrationClient client(serverHostFor(account));

    std::cout << "[verify] submitting code for session " << pending.sessionId << "\n";
    json verifyBody = {{"code", code}};
    HttpResponse verifyResp =
        client.request("PUT", "/v1/verification/session/" + pending.sessionId + "/code", verifyBody.dump());
    std::cout << "[verify] response: " << verifyResp.status << " " << verifyResp.body << "\n";

    json session;
    try {
        session = json::parse(verifyResp.body);
    } catch (const std::exception&) {
        std::cout << "[verify] FAIL: could not parse session response\n";
        return;
    }
    // A 409 here can still mean "already verified from a prior attempt" -
    // trust the parsed .verified field over the status code.
    if (!session.value("verified", false)) {
        std::cout << "[verify] FAIL: session not marked verified after submitting code\n";
        return;
    }
    std::cout << "[verify] session confirmed verified, generating fresh identity + prekeys...\n";

    KeyPair aciIdentity = generateKeyPair();
    KeyPair pniIdentity = generateKeyPair();
    int64_t registrationId = randomRegistrationId();
    int64_t pniRegistrationId = randomRegistrationId();
    GeneratedPrekeys prekeys = generatePrekeys(aciIdentity.privateKey, pniIdentity.privateKey);

    json body = {
        {"sessionId", pending.sessionId},
        {"recoveryPassword", nullptr},
        {"accountAttributes",
        {{"fetchesMessages", true},
         {"registrationId", registrationId},
         {"pniRegistrationId", pniRegistrationId},
         {"name", nullptr},
         {"capabilities", capabilitiesJson()},
         // No profileKey yet at this point - unrestricted is the simpler
         // valid choice for a fresh account (matches register-verify.js).
         {"unrestrictedUnidentifiedAccess", true},
         {"discoverableByPhoneNumber", true}}},
        {"aciIdentityKey", base64NoPadding(aciIdentity.publicKey)},
        {"pniIdentityKey", base64NoPadding(pniIdentity.publicKey)},
        {"aciSignedPreKey", signedPreKeyJson(prekeys.aciSignedPreKey)},
        {"pniSignedPreKey", signedPreKeyJson(prekeys.pniSignedPreKey)},
        {"aciPqLastResortPreKey", kyberPreKeyJson(prekeys.aciKyberPreKey)},
        {"pniPqLastResortPreKey", kyberPreKeyJson(prekeys.pniKyberPreKey)},
        {"gcmToken", nullptr},
        {"skipDeviceTransfer", true},
        {"requireAtomic", true},
    };

    std::cout << "[verify] POST /v1/registration ...\n";
    HttpResponse regResp = client.request("POST", "/v1/registration", body.dump(), account.e164, pending.password);
    std::cout << "[verify] response: " << regResp.status << " " << regResp.body << "\n";
    if (regResp.status != 200) {
        std::cout << "[verify] FAIL: registration rejected\n";
        return;
    }

    json parsed = json::parse(regResp.body);
    FinishedAccount finished;
    finished.e164 = account.e164;
    finished.aci = parsed.at("uuid").get<std::string>();
    finished.pni = parsed.at("pni").get<std::string>();
    finished.password = pending.password;
    finished.deviceId = 1;
    finished.registrationId = registrationId;
    finished.pniRegistrationId = pniRegistrationId;
    finished.aciIdentity = aciIdentity;
    finished.pniIdentity = pniIdentity;
    finished.prekeys = prekeys;
    finished.flow = "standalone";
    saveFinishedAccount(storage, finished);
    deletePending(config.global, accountName);
    if (!resolved.existedInConfig) appendAccountSection(configPath, accountName, account.e164);

    std::cout << "[verify] PASS: registered and saved account '" << accountName << "' (aci " << finished.aci
              << ")\n";
}

// ---- Flow B: device linking via QR ----

void cmdLink(const DaemonConfig& config, const std::string& configPath, const std::string& accountName) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    requireNoExistingAccount(storage, accountName);

    ResolvedAccount resolved = resolveAccount(config, accountName);
    AccountConfig account = resolved.account;

    ProvisioningClient provisioning(kCaCertPath);
    std::cout << "[link] connecting to provisioning socket...\n";
    ProvisionMessageResult provisioned = provisioning.waitForProvisionMessage();
    std::cout << "[link] decrypted provisioning message OK for " << provisioned.e164 << ", finishing linking...\n";

    // e164 comes straight from the scanned account's own ProvisionMessage
    // - no --e164 needed upfront for `link` at all, unlike `register`.
    std::string finalE164 = !account.e164.empty() ? account.e164 : provisioned.e164;
    if (!account.e164.empty() && !provisioned.e164.empty() && provisioned.e164 != account.e164) {
        std::cout << "[link] WARNING: linked number (" << provisioned.e164
                  << ") does not match this account's configured e164 (" << account.e164
                  << ") - saving under the configured e164 anyway; only the identity/keys come from the scan.\n";
        finalE164 = account.e164;
    }
    requireE164NotUsedByOtherAccount(config, accountName, finalE164);

    KeyPair aciIdentity{provisioned.aciIdentityKeyPrivate, provisioned.aciIdentityKeyPublic};
    KeyPair pniIdentity{provisioned.pniIdentityKeyPrivate, provisioned.pniIdentityKeyPublic};
    int64_t registrationId = randomRegistrationId();
    int64_t pniRegistrationId = randomRegistrationId();
    GeneratedPrekeys prekeys = generatePrekeys(aciIdentity.privateKey, pniIdentity.privateKey);
    // This device's own credentials for all future authenticated calls -
    // generated locally, sent as the Basic auth password on the finishing
    // PUT /v1/devices/link call, becoming this device's permanent password
    // from the server's point of view (matches link-new-device.js).
    std::string ourPassword = base64NoPadding(randomBytes(18));

    json body = {
        {"verificationCode", provisioned.provisioningCode},
        {"accountAttributes",
        {{"fetchesMessages", true},
         {"registrationId", registrationId},
         {"pniRegistrationId", pniRegistrationId},
         {"name", nullptr},
         {"capabilities", capabilitiesJson()}}},
        {"aciSignedPreKey", signedPreKeyJson(prekeys.aciSignedPreKey)},
        {"pniSignedPreKey", signedPreKeyJson(prekeys.pniSignedPreKey)},
        {"aciPqLastResortPreKey", kyberPreKeyJson(prekeys.aciKyberPreKey)},
        {"pniPqLastResortPreKey", kyberPreKeyJson(prekeys.pniKyberPreKey)},
        {"gcmToken", nullptr},
    };

    RegistrationClient client(serverHostFor(account));
    std::cout << "[link] PUT /v1/devices/link ...\n";
    HttpResponse resp = client.request("PUT", "/v1/devices/link", body.dump(), provisioned.aci, ourPassword);
    std::cout << "[link] response: " << resp.status << " " << resp.body << "\n";
    if (resp.status != 200) {
        std::cout << "[link] FAIL: linking rejected\n";
        return;
    }

    json parsed = json::parse(resp.body);
    FinishedAccount finished;
    finished.e164 = finalE164;
    finished.aci = parsed.at("uuid").get<std::string>();
    finished.pni = parsed.at("pni").get<std::string>();
    finished.password = ourPassword;
    finished.deviceId = parsed.at("deviceId").get<int>();
    finished.registrationId = registrationId;
    finished.pniRegistrationId = pniRegistrationId;
    finished.aciIdentity = aciIdentity;
    finished.pniIdentity = pniIdentity;
    finished.prekeys = prekeys;
    finished.flow = "linked";
    finished.profileKey = provisioned.profileKey;
    finished.accountEntropyPool = provisioned.accountEntropyPool;
    finished.mediaRootBackupKey = provisioned.mediaRootBackupKey;
    saveFinishedAccount(storage, finished);
    if (!resolved.existedInConfig) appendAccountSection(configPath, accountName, finalE164);

    std::cout << "[link] PASS: linked and saved account '" << accountName << "' (aci " << finished.aci << ", device "
              << finished.deviceId << ")\n";
}

// ---- Local account removal ----

// Wipes every row for this account (identity keys, prekeys, sessions,
// remote identities, cached/synced contacts, the account row itself) from
// the shared local database. Purely local: does NOT contact Signal's
// servers, so it does not unlink/deregister the real account there -
// intended for cleaning up an account whose real-side registration is
// already gone (real unlink, real delete-account, or a local number that
// was never actually verified) so its dead key material doesn't linger
// and block reusing the account name (see requireNoExistingAccount()).
void cmdUnlink(const DaemonConfig& config, const std::string& accountName) {
    Storage storage(config.global.dbPath, config.global.dbKey, accountName);
    if (!storage.hasAccount()) {
        throw std::runtime_error("account '" + accountName + "' has no saved account in the database - nothing to unlink");
    }
    AccountRecord account = storage.loadAccount();
    storage.deleteAccount();
    std::cout << "[unlink] removed all local data for account '" << accountName << "' (e164=" << account.e164
              << ")\n";
    std::cout << "[unlink] this was LOCAL ONLY - it does not unlink or delete the account on Signal's real servers.\n";
    std::cout << "[unlink] the [account." << accountName
              << "] section in the config file was left in place - remove it yourself (and SIGHUP the daemon, or "
                 "restart it) if you don't want it to try starting this account again.\n";
}

void printUsage() {
    std::cerr
        << "usage:\n"
          "  signal2sip-gendb <account-name> register --e164 <e164> [sms|voice] [--config <path>]\n"
          "  signal2sip-gendb <account-name> register-captcha <token> [--config <path>]\n"
          "  signal2sip-gendb <account-name> verify <code> [--config <path>]\n"
          "  signal2sip-gendb <account-name> link [--config <path>]\n"
          "  signal2sip-gendb <account-name> unlink [--config <path>]\n"
          "\n"
          "`unlink` wipes this account's local data (keys, sessions, cached contacts) from the database. It is\n"
          "LOCAL ONLY - it does not contact Signal's servers, so use it after the account is already gone on the\n"
          "real side (a real unlink/delete-account done elsewhere), not as a way to perform that unlink itself.\n"
          "\n"
          "Config file defaults to /etc/signal2sip/signal2sip.conf (else ./signal2sip.conf), same as\n"
          "signal2sip-daemon. Its [global] section (db_path/db_key) is bootstrapped automatically on a clean\n"
          "first run: db_path defaults to /var/lib/signal2sip/signal2sip.db, and db_key is freshly generated\n"
          "and printed once (back it up - it's the passphrase for every account's encrypted keys) - but only\n"
          "when no database file exists at db_path yet; otherwise gendb refuses rather than guess.\n"
          "[account.<name>] does NOT need to exist yet either - `register --e164 ...`/`link` can target a\n"
          "brand-new name, and gendb appends the matching section to the config file once the account is real.\n";
}

struct ParsedArgs {
    std::string accountName;
    std::string command;
    std::vector<std::string> positional; // command-specific, in order (transport/token/code)
    std::string e164;
    std::string configPath;
};

ParsedArgs parseArgs(int argc, char** argv) {
    std::vector<std::string> rest;
    ParsedArgs result;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--e164" && i + 1 < argc) {
            result.e164 = argv[++i];
        } else if (arg == "--config" && i + 1 < argc) {
            result.configPath = argv[++i];
        } else {
            rest.push_back(arg);
        }
    }
    if (rest.size() < 2) throw std::runtime_error("missing <account-name> <command>");
    result.accountName = rest[0];
    result.command = rest[1];
    result.positional.assign(rest.begin() + 2, rest.end());
    return result;
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage();
            return 0;
        }
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    int exitCode = 0;
    ParsedArgs args;
    try {
        args = parseArgs(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "[gendb] error: " << e.what() << "\n";
        printUsage();
        curl_global_cleanup();
        return 1;
    }

    try {
        std::string configPath = resolveGendbConfigPath(args.configPath);
        bootstrapGlobalConfigIfNeeded(configPath);
        DaemonConfig config = DaemonConfig::load(configPath);

        if (args.command == "register") {
            std::string transport = args.positional.empty() ? "sms" : args.positional[0];
            cmdRegister(config, args.accountName, args.e164, transport);
        } else if (args.command == "register-captcha") {
            if (args.positional.empty()) throw std::runtime_error("register-captcha needs a <token>");
            cmdRegisterCaptcha(config, args.accountName, args.positional[0]);
        } else if (args.command == "verify") {
            if (args.positional.empty()) throw std::runtime_error("verify needs a <code>");
            cmdVerify(config, configPath, args.accountName, args.positional[0]);
        } else if (args.command == "link") {
            cmdLink(config, configPath, args.accountName);
        } else if (args.command == "unlink") {
            cmdUnlink(config, args.accountName);
        } else {
            printUsage();
            exitCode = 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "[gendb] error: " << e.what() << "\n";
        exitCode = 1;
    }

    curl_global_cleanup();
    return exitCode;
}
