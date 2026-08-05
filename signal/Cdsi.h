#pragma once

// Real Signal Contact Discovery Service (CDSI) lookup - resolves an e164
// phone number to its current ACI/PNI, the missing piece for calling/
// messaging an account signal2sip has never had contact with before (see
// project docs: GET /v2/keys/{e164}/* 404s on the real server, only a
// ServiceId works there - CDSI is how a real Signal client turns "someone's
// phone number" into that ServiceId in the first place).
//
// Not a REST call - CDSI runs inside an attested SGX enclave (Intel Icelake,
// see signalapp/ContactDiscoveryService-Icelake for the server side) reached
// over a Noise-encrypted channel, so the client has to do remote attestation
// before it can send anything. All of that (attestation, Noise handshake,
// the request/response wire format) is already implemented in the exact
// libsignal-ffi build signal2sip already links (`signal_cdsi_lookup_*` in
// signal_ffi.h) - this file is just the C++ plumbing around it: an async
// Tokio runtime + ConnectionManager (a subsystem signal2sip's own
// AuthSocket-based networking never needed before), and the promise-
// completion callback pattern those calls use instead of a plain return
// value.

#include <string>
#include <vector>

namespace signal2sip {

struct CdsiLookupResult {
    std::string e164;
    std::string aci;  // empty if this e164 isn't on Signal at all
    std::string pni;  // empty alongside aci; can be set with aci empty (PNI known, ACI not - see cdsi.proto)
};

// `username`/`password` are NOT the account's own persistent Signal-Server
// credentials (confirmed live 08-04: the real CDSI service rejects those
// with 401) - they're a separate, short-lived (24h TTL) token pair minted
// specifically for the directory/CDS service, fetched via
// `GET /v2/directory/auth` on the account's normal authenticated socket
// (see Signal-Server's DirectoryV2Controller.getAuthToken() /
// ExternalServiceCredentials - {"username": ..., "password": ...}). The
// caller is responsible for fetching that token first (see
// cdsi_lookup_test.cpp) - this function doesn't take an AuthSocket at all,
// to keep it decoupled from signal2sip's own networking the same way the
// rest of this directory (Crypto.cpp, PreKeys.cpp) already is. CDSI
// lookups are rate-limited per authenticated account, not anonymous - there
// is no unauthenticated path.
std::vector<CdsiLookupResult> cdsiLookup(const std::string& username, const std::string& password,
                                          const std::vector<std::string>& e164s);

}  // namespace signal2sip
