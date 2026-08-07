#pragma once

// Fetches real Signal contact data (e164 <-> ACI/PNI + profileKey) from
// Signal's StorageService - the actual multi-device contact-sync mechanism
// a real linked device (Signal Desktop, or this project's own gendb-linked
// accounts) uses to learn what its primary device already knows. Built
// 2026-08-05 specifically to let signal2sip resolve a genuinely-mutual
// real contact's ACI locally, instead of only ever getting PNI-only from a
// cold CDSI e164 lookup (see project memory
// project_signal2sip_cdsi_cold_call.md's "UAK/contact-sync" section for
// the full "why" - CDS only reveals ACI via a verified aci_uak_pairs
// check, which itself needs an already-cached profile key; this is where
// that cache comes from for real contacts).

#include <string>
#include <vector>

#include "../signal/AuthSocket.h"
#include "../storage/Storage.h"

namespace signal2sip {

struct StorageContact {
    std::string aci;  // may be empty (not every contact record has one)
    std::string pni;  // may be empty
    std::string e164; // may be empty (e.g. a username-only contact)
    Bytes profileKey; // may be empty
    std::string givenName;  // ContactRecord.givenName - may be empty
    std::string familyName; // ContactRecord.familyName - may be empty
};

// Fetches every CONTACT record from the account's real StorageService
// manifest. `socket` only needs to be connected/authenticated as usual
// (used for the initial GET /v1/storage/auth token fetch, which - unlike
// the manifest/item fetches themselves - is available over the normal
// chat.signal.org AuthSocket). `accountEntropyPool` is this account's own
// stored one (Storage::loadAccount()'s AccountRecord::account_entropy_pool)
// - the whole storage service key is derived from it locally, no SVR/PIN
// network round-trip needed. Throws on any failure (network, decrypt,
// parse) - caller decides whether that's fatal or just "no contacts learned
// this time" (e.g. a register-flow account with no real entropy pool/no
// real contacts to sync will legitimately always fail here).
std::vector<StorageContact> fetchStorageContacts(AuthSocket& socket, const std::string& accountEntropyPool);

} // namespace signal2sip
