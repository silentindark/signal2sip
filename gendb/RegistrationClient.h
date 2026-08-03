#pragma once

// Plain HTTPS REST client, C++ port of layer1/registrationSession.js's
// shared HTTP helper (used by register-start.js/register-captcha.js/
// register-verify.js for Flow A) and link-new-device.js's putDevicesLink
// (Flow B's finishing call) - both are plain REST, unlike AuthSocket
// (this project's other Signal-Server client), which requires an
// already-authenticated account and talks a request/response protocol
// framed over a persistent WebSocket. Most calls here need no auth at all
// (a verification session id is what ties requests together, not a device
// password); only the finishing call authenticates, with credentials that
// don't exist as a real account yet - whatever password that call
// authenticates with becomes the account's permanent password.
//
// Requires the caller (curl_global_init) to have initialized libcurl once
// per process - not done here, to match the one-CURL-global-per-process
// rule libcurl documents (gendb/main.cpp does this at startup).

#include <string>

namespace signal2sip {

struct HttpResponse {
    long status = 0;
    std::string body;
};

class RegistrationClient {
public:
    // serverHost matches AccountConfig::serverUrl semantics - empty means
    // production ("chat.signal.org").
    explicit RegistrationClient(std::string serverHost = "chat.signal.org");

    // method: "GET"/"POST"/"PUT"/"PATCH". jsonBody may be empty (no body
    // sent). basicAuthUser empty means no Authorization header at all.
    HttpResponse request(const std::string& method, const std::string& path, const std::string& jsonBody = "",
                         const std::string& basicAuthUser = "", const std::string& basicAuthPass = "");

private:
    std::string serverHost_;
};

} // namespace signal2sip
