#include "ContactResolver.h"

#include <ctime>

#include <nlohmann/json.hpp>

#include "../signal/Cdsi.h"

using json = nlohmann::json;

namespace signal2sip {

std::string resolveOutgoingTarget(AuthSocket& socket, Storage& storage, const std::string& target,
                                   uint32_t ttlSec) {
    if (target.empty() || target[0] != '+') return target;  // already a ServiceId, nothing to resolve

    if (std::optional<ResolvedContactRecord> cached = storage.loadResolvedContact(target)) {
        int64_t ageSec = static_cast<int64_t>(std::time(nullptr)) - cached->resolved_at;
        if (ageSec < static_cast<int64_t>(ttlSec)) {
            if (!cached->aci.empty()) return cached->aci;
            if (!cached->pni.empty()) return cached->pni;
            throw std::runtime_error(target + " is not on Signal (cached CDSI result)");
        }
        // Older than resolved_contact_ttl_sec - fall through and re-resolve
        // rather than trust a possibly-stale mapping (e.g. the target
        // changed numbers - see project notes on PNI vs ACI stability).
    }

    // CDSI itself is a separate libsignal `net` transport (see Cdsi.h) -
    // this GET is only to fetch the short-lived directory-service token it
    // needs, over the account's own already-connected/authenticated
    // AuthSocket.
    AuthSocket::Response authResponse = socket.request("GET", "/v2/directory/auth");
    if (authResponse.status != 200) {
        throw std::runtime_error("GET /v2/directory/auth -> status " + std::to_string(authResponse.status));
    }
    json authToken = json::parse(std::string(authResponse.body.begin(), authResponse.body.end()));

    std::vector<CdsiLookupResult> results = cdsiLookup(
        authToken.at("username").get<std::string>(), authToken.at("password").get<std::string>(), {target});
    if (results.empty()) {
        throw std::runtime_error("CDSI lookup for " + target + " returned no result");
    }

    const CdsiLookupResult& result = results.front();
    storage.saveResolvedContact(target, result.aci, result.pni);

    if (!result.aci.empty()) return result.aci;
    if (!result.pni.empty()) return result.pni;
    throw std::runtime_error(target + " is not on Signal (CDSI lookup found nothing)");
}

} // namespace signal2sip
