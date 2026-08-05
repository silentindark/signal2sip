#include "Cdsi.h"

#include <condition_variable>
#include <mutex>

#include "FfiUtil.h"

// signal_cdsi_lookup_new/_complete are libsignal's only *async* C ABI calls
// this project uses - everything else (session establishment, prekey
// bundles, ...) is a synchronous signal_* call wrapped in checkError().
// Their completion is reported via a SignalCPromise<T>: a plain-C struct of
// {complete function pointer, opaque context, cancellation_id}, filled in
// by signal_cdsi_lookup_new/_complete's own synchronous return (which can
// itself fail immediately, e.g. bad arguments - checked the normal way) and
// then invoked exactly once, from some Rust/Tokio worker thread, once the
// real network round trip finishes. Confirmed against libsignal's own
// bridge source (rust/bridge/shared/types/src/ffi/futures.rs,
// FutureResultReporter::report_to): after calling `complete`, Rust
// `std::mem::forget`s the result - ownership fully transfers to us, we must
// eventually free it (signal_cdsi_lookup_destroy /
// signal_free_lookup_response_entry_list below), Rust will not.
//
// awaitLookupHandle/awaitLookupResponse below just block the calling thread
// on a condition_variable until that one callback fires - there is no
// other async work happening in this process that needs the calling
// thread free in the meantime, so a plain blocking wait is simpler and
// safer than trying to weave this into some larger event loop.

namespace signal2sip {

namespace {

// libsignal bakes in every CDSI/chat/SVR host and trusted enclave
// measurement per Environment value - Prod=1 (see libsignal's
// rust/bridge/shared/types/src/net.rs Environment enum) means "the real
// production Signal service", same as every other real account this
// project already talks to. No manual host/mrenclave configuration needed
// here, unlike a hand-rolled CDSI client would require.
constexpr uint8_t kEnvironmentProd = 1;
constexpr const char* kUserAgent = "signal2sip";

// 16 raw UUID bytes (CDSI's wire format for both ACI and PNI - see
// cdsi.proto's e164_pni_aci_triples comment) -> standard 8-4-4-4-12 hex
// string, or "" for the all-zero sentinel meaning "not found" - matches
// what ProtocolStores/AuthSocket elsewhere in this project already expect
// an ACI/PNI string to look like.
std::string formatUuidOrEmpty(const uint8_t bytes[16]) {
    bool allZero = true;
    for (int i = 0; i < 16; i++) {
        if (bytes[i] != 0) {
            allZero = false;
            break;
        }
    }
    if (allZero) return "";

    char buf[37];
    std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", bytes[0],
                  bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                  bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]);
    return std::string(buf);
}

// Starts the lookup (the attested-enclave handshake + auth) and blocks
// until libsignal hands back a lookup handle - the actual e164 lookup
// traffic doesn't happen until awaitLookupResponse() below.
SignalMutPointerCdsiLookup awaitLookupHandle(SignalConstPointerTokioAsyncContext runtime,
                                              SignalConstPointerConnectionManager manager,
                                              const std::string& username, const std::string& password,
                                              SignalConstPointerLookupRequest request) {
    struct State {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        SignalFfiError* error = nullptr;
        SignalMutPointerCdsiLookup handle{};
    } state;

    SignalCPromiseMutPointerCdsiLookup promise{};
    promise.context = &state;
    promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_SignalMutPointerCdsiLookup result,
                           const void* context) {
        auto* st = const_cast<State*>(static_cast<const State*>(context));
        std::lock_guard<std::mutex> lock(st->mutex);
        st->error = error;
        if (!error && result) st->handle = *result;
        st->done = true;
        st->cv.notify_one();
    };

    checkError(signal_cdsi_lookup_new(&promise, runtime, manager, reinterpret_cast<const int8_t*>(username.c_str()),
                                       reinterpret_cast<const int8_t*>(password.c_str()), request));

    std::unique_lock<std::mutex> lock(state.mutex);
    state.cv.wait(lock, [&] { return state.done; });
    lock.unlock();
    checkError(state.error);
    return state.handle;
}

// Runs the actual lookup traffic over the now-attested channel and blocks
// until the real response (or a rate-limit/network error) comes back.
std::vector<CdsiLookupResult> awaitLookupResponse(SignalConstPointerTokioAsyncContext runtime,
                                                   SignalConstPointerCdsiLookup lookup) {
    struct State {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        SignalFfiError* error = nullptr;
        SignalFfiCdsiLookupResponse response{};
        bool hasResponse = false;
    } state;

    SignalCPromiseFfiCdsiLookupResponse promise{};
    promise.context = &state;
    promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_SignalFfiCdsiLookupResponse result,
                           const void* context) {
        auto* st = const_cast<State*>(static_cast<const State*>(context));
        std::lock_guard<std::mutex> lock(st->mutex);
        st->error = error;
        if (!error && result) {
            st->response = *result;
            st->hasResponse = true;
        }
        st->done = true;
        st->cv.notify_one();
    };

    checkError(signal_cdsi_lookup_complete(&promise, runtime, lookup));

    std::unique_lock<std::mutex> lock(state.mutex);
    state.cv.wait(lock, [&] { return state.done; });
    lock.unlock();
    checkError(state.error);

    std::vector<CdsiLookupResult> results;
    if (state.hasResponse) {
        results.reserve(state.response.entries.length);
        for (size_t i = 0; i < state.response.entries.length; i++) {
            const SignalFfiCdsiLookupResponseEntry& entry = state.response.entries.base[i];
            CdsiLookupResult result;
            // Wire format is a plain base-10 phone number (no '+', see
            // cdsi.proto) packed into a uint64 - "+" here is just this
            // project's own e164 string convention, same as everywhere
            // else (AuthSocket usernames, Config's e164 fields, ...).
            result.e164 = "+" + std::to_string(entry.e164);
            result.aci = formatUuidOrEmpty(entry.rawAciUuid);
            result.pni = formatUuidOrEmpty(entry.rawPniUuid);
            results.push_back(std::move(result));
        }
        // Frees the entries array itself (the per-entry structs are
        // fixed-size, no nested allocations) - state.response is a stack
        // copy of the pointer+length pair, this is the one and only owner.
        signal_free_lookup_response_entry_list(state.response.entries);
    }
    return results;
}

}  // namespace

std::vector<CdsiLookupResult> cdsiLookup(const std::string& username, const std::string& password,
                                          const std::vector<std::string>& e164s) {
    SignalMutPointerTokioAsyncContext runtimeMut{};
    checkError(signal_tokio_async_context_new(&runtimeMut));
    SignalConstPointerTokioAsyncContext runtime{runtimeMut.raw};

    // A null SignalMutPointerBridgedStringMap (the "no remote config
    // overrides" case, which is all this ever needs) is NOT accepted here -
    // confirmed live: signal_connection_manager_new rejects it with a
    // "null pointer" error. Rust's own null-pointer-argument checks in this
    // bridge apparently require a real (possibly empty) map object instead
    // of treating a null pointer as "absent".
    SignalMutPointerBridgedStringMap remoteConfig{};
    checkError(signal_bridged_string_map_new(&remoteConfig, /*initial_capacity=*/0));

    SignalMutPointerConnectionManager managerMut{};
    checkError(signal_connection_manager_new(&managerMut, kEnvironmentProd,
                                              reinterpret_cast<const int8_t*>(kUserAgent), remoteConfig,
                                              /*build_variant=*/0));
    SignalConstPointerConnectionManager manager{managerMut.raw};
    checkError(signal_bridged_string_map_destroy(remoteConfig));

    SignalMutPointerLookupRequest requestMut{};
    checkError(signal_lookup_request_new(&requestMut));
    SignalConstPointerLookupRequest request{requestMut.raw};
    for (const auto& e164 : e164s) {
        checkError(signal_lookup_request_add_e164(request, reinterpret_cast<const int8_t*>(e164.c_str())));
    }

    SignalMutPointerCdsiLookup lookup = awaitLookupHandle(runtime, manager, username, password, request);
    checkError(signal_lookup_request_destroy(requestMut));

    std::vector<CdsiLookupResult> results = awaitLookupResponse(runtime, SignalConstPointerCdsiLookup{lookup.raw});

    checkError(signal_cdsi_lookup_destroy(lookup));
    checkError(signal_connection_manager_destroy(managerMut));
    checkError(signal_tokio_async_context_destroy(runtimeMut));
    return results;
}

}  // namespace signal2sip
