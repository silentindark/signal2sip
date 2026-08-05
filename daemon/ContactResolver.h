#pragma once

// Resolves an outgoing-call target (outgoing_call_target config, see
// Config.h) to a real ServiceId (ACI or PNI) signal2sip_call_start_outgoing
// can use - transparently, so a plain e164 phone number works there too,
// not just an already-known ACI/UUID. Ties together native/signal/Cdsi.h
// (the real lookup), AuthSocket (fetching the short-lived directory-
// service token CDSI needs - see Cdsi.h's own doc comment) and Storage
// (caching the result so a real, rate-limited CDS lookup only happens once
// per target, not on every daemon restart).

#include <cstdint>
#include <string>

#include "../signal/AuthSocket.h"
#include "../storage/Storage.h"

namespace signal2sip {

// `target` is either already a ServiceId (any string not starting with
// '+', e.g. an ACI/PNI UUID) - returned unchanged, no network/DB access at
// all - or an e164 phone number ('+' prefixed), which gets resolved via
// `storage`'s cache first, falling back to a real CDSI lookup over
// `socket` (must already be connected - reuses the account's own normal
// auth). A cached row older than `ttlSec` (see GlobalConfig::
// resolvedContactTtlSec) is treated as a miss and re-resolved. Throws
// std::runtime_error if the target isn't on Signal at all, or if
// resolution otherwise fails.
std::string resolveOutgoingTarget(AuthSocket& socket, Storage& storage, const std::string& target,
                                   uint32_t ttlSec);

} // namespace signal2sip
