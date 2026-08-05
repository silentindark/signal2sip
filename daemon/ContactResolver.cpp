#include "ContactResolver.h"

#include <ctime>

#include <nlohmann/json.hpp>

#include "../signal/Cdsi.h"

using json = nlohmann::json;

namespace signal2sip {

std::string resolveOutgoingTarget(AuthSocket& socket, Storage& storage, const std::string& target,
                                   uint32_t ttlSec) {
    if (target.empty() || target[0] != '+') return target;  // already a ServiceId, nothing to resolve

    // Prefer a real contact learned via StorageServiceSync (see that file's
    // own doc comment) over a CDS lookup - a genuinely mutual real contact
    // has an ACI here regardless of CDS/PNP status, unlike CDS which can
    // only ever hand back PNI for a "cold" e164 (see
    // project_signal2sip_cdsi_cold_call.md's "UAK/contact-sync" section for
    // the full "why"). Only synced-in accounts (a real account_entropy_pool,
    // i.e. gendb-linked) will ever have rows here at all.
    if (std::optional<SyncedContactRecord> synced = storage.loadSyncedContact(target)) {
        if (!synced->aci.empty()) return synced->aci;
    }

    if (std::optional<ResolvedContactRecord> cached = storage.loadResolvedContact(target)) {
        int64_t ageSec = static_cast<int64_t>(std::time(nullptr)) - cached->resolved_at;
        if (ageSec < static_cast<int64_t>(ttlSec)) {
            if (!cached->aci.empty()) return cached->aci;
            if (!cached->pni.empty()) return "PNI:" + cached->pni;
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

    // Signal-Server's ServiceIdentifier.valueOf() (identity/ServiceIdentifier.java)
    // tries to parse any bare string as an ACI first and only falls back to
    // PNI if that fails - PniServiceIdentifier.valueOf() explicitly requires
    // a "PNI:" string prefix, rejecting anything else with "PNI account
    // identifier did not start with \"PNI:\" prefix". Found live 2026-08-05:
    // without this, a resolved PNI (bare UUID, indistinguishable from a
    // valid-looking ACI UUID) got silently misinterpreted server-side as a
    // request for an ACI with that same UUID value - which of course
    // doesn't exist - so every PNI-only CDSI resolution's outgoing call
    // 404'd on GET /v2/keys/{uuid}/* (and would have equally broken
    // PUT /v1/messages/{destination}, which takes the identical
    // ServiceIdentifier path type) even for a target with completely normal,
    // present PNI prekeys - this was never actually a "PNI has no prekeys"
    // protocol limitation.
    if (!result.aci.empty()) return result.aci;
    if (!result.pni.empty()) return "PNI:" + result.pni;
    throw std::runtime_error(target + " is not on Signal (CDSI lookup found nothing)");
}

} // namespace signal2sip
