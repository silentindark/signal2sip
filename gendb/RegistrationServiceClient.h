#pragma once

// Flow A (standalone SMS/voice registration) transport, built on
// libsignal's own C FFI registration-service client
// (signal_registration_service_* in signal_ffi.h) instead of hand-rolled
// libcurl REST calls (util/RegistrationClient.h/.cpp) - same motivation
// and pattern as AuthSocket's migration onto libsignal-net-chat (see
// AuthSocket.h's own doc comment, and project memory
// signal2sip-registrationclient-ffi-migration for the full scoping this
// followed). Flow B's finishing call (PUT /v1/devices/link,
// gendb::cmdLink) and StorageServiceSync's plain REST calls are OUT OF
// SCOPE for this class - neither has any signal_registration_service_*
// coverage (device linking needs a real device name, which this FFI
// family has no way to set at all) - both stay on RegistrationClient.
//
// gendb is a short-lived CLI process invoked once per registration step
// (`register`, then `register-captcha`, then `verify` - three separate
// process runs) - unlike AuthSocket's long-lived daemon connection, a
// RegistrationServiceClient's underlying RegistrationService handle
// (and the semi-persistent unauth chat connection it opens) only needs
// to live for one process's single call to createSession()/resumeSession()
// through to whatever that same invocation's flow ends on. The session
// itself (identified by sessionId, a plain string) is what persists
// across invocations - via the existing PendingRegistration file, same
// as before this migration - not the RegistrationService handle itself.

#include <cstdint>
#include <string>
#include <vector>

#include "AccountFinisher.h"
#include "../signal/FfiUtil.h"

namespace signal2sip {

struct RegistrationSessionState {
    bool allowedToRequestCode = false;
    // Raw ChallengeOption names this session still needs satisfied -
    // "captcha" / "pushChallenge", matching the values callers already
    // compare against (see cmdRegister's needsCaptcha/needsPushChallenge).
    std::vector<std::string> requestedInformation;
};

struct RegisteredAccount {
    std::string aci;
    std::string pni;
};

class RegistrationServiceClient {
public:
    RegistrationServiceClient();
    ~RegistrationServiceClient();

    RegistrationServiceClient(const RegistrationServiceClient&) = delete;
    RegistrationServiceClient& operator=(const RegistrationServiceClient&) = delete;

    // Exactly one of createSession()/resumeSession() must be called
    // before anything else, and at most once.
    RegistrationSessionState createSession(const std::string& e164);
    RegistrationSessionState resumeSession(const std::string& sessionId, const std::string& e164);

    // Valid only after createSession()/resumeSession() - the session id
    // to persist (e.g. into gendb's PendingRegistration file) so a later
    // process invocation can resumeSession() with it.
    std::string sessionId() const;

    RegistrationSessionState submitCaptcha(const std::string& captchaToken);
    RegistrationSessionState requestVerificationCode(const std::string& transport); // "sms" | "voice"
    bool submitVerificationCode(const std::string& code); // returns session.verified

    // accountPassword becomes this device's permanent Signal password
    // (same role as RegistrationClient-based cmdVerify's `pending.password`
    // Basic-Auth credential) - caller generates and persists it same as
    // before. aciIdentity/pniIdentity/prekeys are the already-generated
    // identity+prekey material (PreKeys.h/AccountFinisher.h types) -
    // generation itself is untouched by this migration, only how the
    // already-generated wire values get sent changes.
    RegisteredAccount registerAccount(const std::string& accountPassword, int64_t registrationId,
                                      int64_t pniRegistrationId, const KeyPair& aciIdentity,
                                      const KeyPair& pniIdentity, const GeneratedPrekeys& prekeys);

private:
    struct Impl;
    Impl* impl_;
};

} // namespace signal2sip
