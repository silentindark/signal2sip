#include "RegistrationServiceClient.h"

#include <signal_ffi.h>

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <stdexcept>
#include <vector>

#include "../signal/FfiUtil.h"

// Every async signal_registration_service_* call follows the same
// promise/condition_variable blocking pattern AuthSocket.cpp already
// established for libsignal-net-chat (see that file's own doc comment
// for the general contract - complete() fires later from an arbitrary
// tokio worker thread, never the calling thread). Unlike AuthSocket,
// gendb is a short-lived CLI process making at most a handful of these
// calls per invocation (no reconnect watchdog, no abandon/late-completion
// hazard worth guarding against - the process just blocks until done or
// throws).

namespace signal2sip {

namespace {

constexpr uint8_t kEnvironmentProd = 1;
constexpr uint8_t kBuildVariantProduction = 0;
constexpr const char* kUserAgent = "signal2sip";

constexpr uint8_t kIdentityTypeAci = 0; // matches libsignal's ServiceIdKind::Aci discriminant
constexpr uint8_t kIdentityTypePni = 1; // ServiceIdKind::Pni

// Same construction AuthSocket.cpp's makeConnectionManager() uses -
// signal_connection_manager_new rejects a null remote_config map, so an
// empty one is built and freed right after (that copy is only read
// during this call, not held).
SignalMutPointerConnectionManager makeConnectionManager() {
    SignalMutPointerBridgedStringMap remoteConfig{};
    checkError(signal_bridged_string_map_new(&remoteConfig, /*initial_capacity=*/0));
    SignalMutPointerConnectionManager manager{};
    checkError(signal_connection_manager_new(&manager, kEnvironmentProd,
                                              reinterpret_cast<const int8_t*>(kUserAgent), remoteConfig,
                                              kBuildVariantProduction));
    checkError(signal_bridged_string_map_destroy(remoteConfig));
    return manager;
}

// SignalFfiConnectChatBridgeStruct's ctx for create_session/resume_session
// - wraps a *borrowed* view of a ConnectionManager this class already
// owns for its whole lifetime (see Impl below). destroy() here only ever
// frees this tiny wrapper, never the real ConnectionManager - safe
// regardless of exactly when/how long libsignal-net holds onto ctx
// internally (unverified from the header alone, and not worth the risk
// of guessing wrong - see registerAccount()'s own comment on a related
// lifetime question this file deliberately does NOT guess on).
struct ConnectChatBridgeCtx {
    SignalConnectionManager* connectionManagerRaw;
};

SignalType_ConstPointer_SignalConnectionManager getConnectionManagerCallback(void* ctx) {
    return SignalType_ConstPointer_SignalConnectionManager{static_cast<ConnectChatBridgeCtx*>(ctx)->connectionManagerRaw};
}

void destroyConnectChatBridgeCtx(void* ctx) { delete static_cast<ConnectChatBridgeCtx*>(ctx); }

// Owns the backing storage for a SignalBorrowedBytestringArray (a
// concatenated-bytes + per-item-length encoding) - keep alive for the
// duration of whatever FFI call borrows view().
struct BorrowedBytestrings {
    std::string concatenated;
    std::vector<size_t> lengths;

    SignalBorrowedBytestringArray view() const {
        return SignalBorrowedBytestringArray{
            SignalBorrowedBuffer{reinterpret_cast<const uint8_t*>(concatenated.data()), concatenated.size()},
            SignalBorrowedSliceOfusize{lengths.data(), lengths.size()}};
    }
};

BorrowedBytestrings makeBytestrings(const std::vector<std::string>& items) {
    BorrowedBytestrings storage;
    for (const auto& s : items) {
        storage.concatenated += s;
        storage.lengths.push_back(s.size());
    }
    return storage;
}

// signal_registration_session_get_requested_information() returns one
// byte per ChallengeOption discriminant (ChallengeOption::PushChallenge
// = 0, ChallengeOption::Captcha = 1 - confirmed against
// rust/net/chat/src/api.rs) - map back to the same strings cmdRegister's
// existing needsCaptcha/needsPushChallenge comparisons expect.
std::string challengeOptionName(uint8_t discriminant) {
    switch (discriminant) {
        case 0: return "pushChallenge";
        case 1: return "captcha";
        default: return "unknown";
    }
}

std::string serviceIdString(const SignalType_FixedArray17_uint8_t& binary) {
    SignalCStringPtr str = nullptr;
    checkError(signal_service_id_service_id_string(&str, &binary));
    std::string result(reinterpret_cast<const char*>(str));
    signal_free_string(str);
    return result;
}

} // namespace

struct RegistrationServiceClient::Impl {
    SignalMutPointerTokioAsyncContext asyncContext{};
    SignalMutPointerConnectionManager connectionManager{};
    SignalMutPointerRegistrationService service{}; // .raw == nullptr until create/resumeSession()

    Impl() {
        checkError(signal_tokio_async_context_new(&asyncContext));
        connectionManager = makeConnectionManager();
    }

    ~Impl() {
        if (service.raw) {
            SignalFfiError* err = signal_registration_service_destroy(service);
            if (err) signal_error_free(err);
        }
        SignalFfiError* err = signal_connection_manager_destroy(connectionManager);
        if (err) signal_error_free(err);
        err = signal_tokio_async_context_destroy(asyncContext);
        if (err) signal_error_free(err);
    }

    SignalConstPointerTokioAsyncContext runtime() const { return SignalConstPointerTokioAsyncContext{asyncContext.raw}; }

    SignalConstPointerFfiConnectChatBridgeStruct buildConnectChat(SignalFfiConnectChatBridgeStruct& storage) {
        storage.ctx = new ConnectChatBridgeCtx{connectionManager.raw};
        storage.get_connection_manager = &getConnectionManagerCallback;
        storage.destroy = &destroyConnectChatBridgeCtx;
        return SignalConstPointerFfiConnectChatBridgeStruct{&storage};
    }

    // Blocking wrapper for create_session/resume_session - both hand
    // back a fresh RegistrationService handle via an identical promise
    // shape. Stores the result on this Impl (service) rather than
    // returning it, since every caller immediately wants it there.
    template <typename CallFn>
    void runCreateOrResume(CallFn&& call) {
        struct State {
            std::mutex mutex;
            std::condition_variable cv;
            bool done = false;
            SignalFfiError* error = nullptr;
            SignalMutPointerRegistrationService result{};
        } state;

        SignalCPromiseMutPointerRegistrationService promise{};
        promise.context = &state;
        promise.complete = [](SignalFfiError* error,
                               SignalType_ConstPointer_SignalMutPointerRegistrationService result,
                               const void* context) {
            auto* st = const_cast<State*>(static_cast<const State*>(context));
            std::lock_guard<std::mutex> lock(st->mutex);
            st->error = error;
            if (!error && result) st->result = *result;
            st->done = true;
            st->cv.notify_one();
        };

        SignalFfiError* callErr = call(promise);
        if (callErr) checkError(callErr);

        std::unique_lock<std::mutex> lock(state.mutex);
        state.cv.wait(lock, [&] { return state.done; });
        lock.unlock();

        if (state.error) checkError(state.error);
        service = state.result;
    }

    // Blocking wrapper for the bool-result async calls (submit_captcha/
    // request_verification_code/submit_verification_code) - same shape
    // AuthSocket.cpp's disconnectAndDestroyBestEffort() already uses for
    // SignalCPromisebool.
    template <typename CallFn>
    void runBoolCall(CallFn&& call) {
        struct State {
            std::mutex mutex;
            std::condition_variable cv;
            bool done = false;
            SignalFfiError* error = nullptr;
        } state;

        SignalCPromisebool promise{};
        promise.context = &state;
        promise.complete = [](SignalFfiError* error, SignalType_ConstPointer_bool /*result*/, const void* context) {
            auto* st = const_cast<State*>(static_cast<const State*>(context));
            std::lock_guard<std::mutex> lock(st->mutex);
            st->error = error;
            st->done = true;
            st->cv.notify_one();
        };

        SignalFfiError* callErr = call(promise);
        if (callErr) checkError(callErr);

        std::unique_lock<std::mutex> lock(state.mutex);
        state.cv.wait(lock, [&] { return state.done; });
        lock.unlock();

        if (state.error) checkError(state.error);
    }

    RegistrationSessionState currentSessionState() {
        SignalMutPointerRegistrationSession session{};
        checkError(
            signal_registration_service_registration_session(&session, SignalConstPointerRegistrationService{service.raw}));

        RegistrationSessionState result;
        checkError(signal_registration_session_get_allowed_to_request_code(
            &result.allowedToRequestCode, SignalConstPointerRegistrationSession{session.raw}));

        SignalOwnedBuffer requestedInfo{};
        checkError(signal_registration_session_get_requested_information(
            &requestedInfo, SignalConstPointerRegistrationSession{session.raw}));
        Bytes requestedInfoBytes = takeOwned(requestedInfo);
        for (uint8_t b : requestedInfoBytes) result.requestedInformation.push_back(challengeOptionName(b));

        checkError(signal_registration_session_destroy(session));
        return result;
    }
};

RegistrationServiceClient::RegistrationServiceClient() : impl_(new Impl()) {}
RegistrationServiceClient::~RegistrationServiceClient() { delete impl_; }

std::string RegistrationServiceClient::sessionId() const {
    SignalCStringPtr str = nullptr;
    checkError(signal_registration_service_session_id(&str, SignalConstPointerRegistrationService{impl_->service.raw}));
    std::string result(reinterpret_cast<const char*>(str));
    signal_free_string(str);
    return result;
}

RegistrationSessionState RegistrationServiceClient::createSession(const std::string& e164) {
    SignalFfiConnectChatBridgeStruct bridgeStorage{};
    SignalConstPointerFfiConnectChatBridgeStruct connectChat = impl_->buildConnectChat(bridgeStorage);

    SignalFfiRegistrationCreateSessionRequest request{};
    request.number = reinterpret_cast<const int8_t*>(e164.c_str());
    request.push_token = nullptr;
    request.mcc = nullptr;
    request.mnc = nullptr;

    impl_->runCreateOrResume([&](SignalCPromiseMutPointerRegistrationService& promise) {
        return signal_registration_service_create_session(&promise, impl_->runtime(), request, connectChat);
    });
    return impl_->currentSessionState();
}

RegistrationSessionState RegistrationServiceClient::resumeSession(const std::string& sessionId,
                                                                   const std::string& e164) {
    SignalFfiConnectChatBridgeStruct bridgeStorage{};
    SignalConstPointerFfiConnectChatBridgeStruct connectChat = impl_->buildConnectChat(bridgeStorage);

    impl_->runCreateOrResume([&](SignalCPromiseMutPointerRegistrationService& promise) {
        return signal_registration_service_resume_session(&promise, impl_->runtime(),
                                                            reinterpret_cast<const int8_t*>(sessionId.c_str()),
                                                            reinterpret_cast<const int8_t*>(e164.c_str()), connectChat);
    });
    return impl_->currentSessionState();
}

RegistrationSessionState RegistrationServiceClient::submitCaptcha(const std::string& captchaToken) {
    SignalConstPointerRegistrationService service{impl_->service.raw};
    impl_->runBoolCall([&](SignalCPromisebool& promise) {
        return signal_registration_service_submit_captcha(&promise, impl_->runtime(), service,
                                                            reinterpret_cast<const int8_t*>(captchaToken.c_str()));
    });
    return impl_->currentSessionState();
}

RegistrationSessionState RegistrationServiceClient::requestVerificationCode(const std::string& transport) {
    SignalConstPointerRegistrationService service{impl_->service.raw};
    SignalBorrowedBytestringArray noLanguages{}; // matches current curl-based flow, which never sent Accept-Language either
    impl_->runBoolCall([&](SignalCPromisebool& promise) {
        return signal_registration_service_request_verification_code(
            &promise, impl_->runtime(), service, reinterpret_cast<const int8_t*>(transport.c_str()),
            reinterpret_cast<const int8_t*>("signal2sip"), noLanguages);
    });
    return impl_->currentSessionState();
}

bool RegistrationServiceClient::submitVerificationCode(const std::string& code) {
    SignalConstPointerRegistrationService service{impl_->service.raw};
    try {
        impl_->runBoolCall([&](SignalCPromisebool& promise) {
            return signal_registration_service_submit_verification_code(
                &promise, impl_->runtime(), service, reinterpret_cast<const int8_t*>(code.c_str()));
        });
    } catch (const std::exception&) {
        // Matches the old RegistrationClient-based cmdVerify's own
        // comment: a rejection here can still mean "already verified
        // from a prior attempt" (e.g. a retried `verify` after the first
        // one's response was lost) - fall through and trust the
        // session's own .verified flag below instead of treating every
        // rejection as fatal.
    }

    SignalMutPointerRegistrationSession session{};
    checkError(signal_registration_service_registration_session(&session, service));
    bool verified = false;
    checkError(
        signal_registration_session_get_verified(&verified, SignalConstPointerRegistrationSession{session.raw}));
    checkError(signal_registration_session_destroy(session));
    return verified;
}

RegisteredAccount RegistrationServiceClient::registerAccount(const std::string& accountPassword,
                                                              int64_t registrationId, int64_t pniRegistrationId,
                                                              const KeyPair& aciIdentity, const KeyPair& pniIdentity,
                                                              const GeneratedPrekeys& prekeys) {
    SignalConstPointerRegistrationService service{impl_->service.raw};

    // --- RegisterAccountRequest: password, skip-device-transfer, and all
    // 6 identity/signed-prekey/pq-prekey setters for BOTH Aci and Pni -
    // register_account() panics server^Wlibsignal-side
    // (RegisterAccountInner's .expect("key was provided")) if any of the
    // 6 aren't set before calling it, so every one below is mandatory,
    // not "as needed".
    SignalMutPointerRegisterAccountRequest request{};
    checkError(signal_register_account_request_create(&request));
    SignalConstPointerRegisterAccountRequest constRequest{request.raw};

    checkError(signal_register_account_request_set_account_password(
        constRequest, reinterpret_cast<const int8_t*>(accountPassword.c_str())));
    checkError(signal_register_account_request_set_skip_device_transfer(constRequest));

    SignalMutPointerPublicKey aciPublicKey = publicKeyDeserialize(aciIdentity.publicKey);
    SignalMutPointerPublicKey pniPublicKey = publicKeyDeserialize(pniIdentity.publicKey);
    checkError(signal_register_account_request_set_identity_public_key(
        constRequest, kIdentityTypeAci, SignalConstPointerPublicKey{aciPublicKey.raw}));
    checkError(signal_register_account_request_set_identity_public_key(
        constRequest, kIdentityTypePni, SignalConstPointerPublicKey{pniPublicKey.raw}));
    checkError(signal_publickey_destroy(aciPublicKey));
    checkError(signal_publickey_destroy(pniPublicKey));

    auto setSignedPreKey = [&](uint8_t identityType, const GeneratedSignedPreKey& key) {
        SignalMutPointerPublicKey pub = publicKeyDeserialize(key.wire.publicKey);
        SignalFfiSignedPublicPreKey ffiKey{};
        ffiKey.key_id = static_cast<uint32_t>(key.wire.keyId);
        ffiKey.public_key_type = SignalFfiPublicKeyTypeECC;
        ffiKey.public_key = pub.raw;
        ffiKey.signature = borrow(key.wire.signature);
        checkError(signal_register_account_request_set_identity_signed_pre_key(constRequest, identityType, ffiKey));
        checkError(signal_publickey_destroy(pub));
    };
    setSignedPreKey(kIdentityTypeAci, prekeys.aciSignedPreKey);
    setSignedPreKey(kIdentityTypePni, prekeys.pniSignedPreKey);

    auto setKyberPreKey = [&](uint8_t identityType, const GeneratedKyberPreKey& key) {
        SignalMutPointerKyberPublicKey pub{};
        checkError(signal_kyber_public_key_deserialize(&pub, borrow(key.wire.publicKey)));
        SignalFfiSignedPublicPreKey ffiKey{};
        ffiKey.key_id = static_cast<uint32_t>(key.wire.keyId);
        ffiKey.public_key_type = SignalFfiPublicKeyTypeKyber;
        ffiKey.public_key = pub.raw;
        ffiKey.signature = borrow(key.wire.signature);
        checkError(
            signal_register_account_request_set_identity_pq_last_resort_pre_key(constRequest, identityType, ffiKey));
        checkError(signal_kyber_public_key_destroy(pub));
    };
    setKyberPreKey(kIdentityTypeAci, prekeys.aciKyberPreKey);
    setKyberPreKey(kIdentityTypePni, prekeys.pniKyberPreKey);

    // --- RegistrationAccountAttributes ---
    // unidentifiedAccessKey: no profileKey exists yet at this point in a
    // fresh registration (matches the old RegistrationClient-based
    // cmdVerify's own comment), so unrestricted access is requested
    // instead - confirmed against Signal-Server's own
    // AccountAttributes.isUnrestrictedUakValid()
    // (unrestrictedUnidentifiedAccess=true short-circuits the check
    // regardless of the UAK value), so the actual 16 bytes here are
    // moot - zero-filled.
    SignalType_FixedArray16_uint8_t zeroUak{};
    // Matches capabilitiesJson()'s true-valued entries only
    // (storage/versionedExpirationTimer/attachmentBackfill are false
    // there, and the FFI attributes builder can only send true-valued
    // capability names at all - confirmed equivalent server-side via
    // DeviceAttributes' Set<DeviceCapability> deserialization, which
    // only tracks presence, not explicit false).
    BorrowedBytestrings capabilities = makeBytestrings({"spqr", "usernameChangeSyncMessage"});

    SignalMutPointerRegistrationAccountAttributes attributes{};
    Bytes unusedRecoveryPassword; // required param, but ignored server-side once a session_id-bound service is
                                  // used (SessionValidation::SessionId, not RecoveryPassword - confirmed in
                                  // rust/net/chat/src/ws/registration/request.rs) - every call here goes through
                                  // create_session/resume_session, so this is always the session_id-bound case.
    checkError(signal_registration_account_attributes_create(
        &attributes, borrow(unusedRecoveryPassword), static_cast<uint16_t>(registrationId),
        static_cast<uint16_t>(pniRegistrationId), /*registration_lock=*/nullptr, &zeroUak,
        /*unrestricted_unidentified_access=*/true, capabilities.view(), /*discoverable_by_phone_number=*/true));
    SignalConstPointerRegistrationAccountAttributes constAttributes{attributes.raw};

    // --- register_account() itself ---
    struct State {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        SignalFfiError* error = nullptr;
        SignalMutPointerRegisterAccountResponse result{};
    } state;

    SignalCPromiseMutPointerRegisterAccountResponse promise{};
    promise.context = &state;
    promise.complete = [](SignalFfiError* error,
                           SignalType_ConstPointer_SignalMutPointerRegisterAccountResponse result,
                           const void* context) {
        auto* st = const_cast<State*>(static_cast<const State*>(context));
        std::lock_guard<std::mutex> lock(st->mutex);
        st->error = error;
        if (!error && result) st->result = *result;
        st->done = true;
        st->cv.notify_one();
    };

    SignalFfiError* callErr =
        signal_registration_service_register_account(&promise, impl_->runtime(), service, constRequest, constAttributes);
    if (callErr) {
        // Not fired at all - matches AuthSocket.cpp's own httpRequest
        // lifetime lesson (see that file's doRequest() comment on a real
        // UAF it hit once from destroying an in-flight request's backing
        // object too early): only destroy request/attributes once we
        // know for certain no async task is still going to read them,
        // which for a same-call synchronous error is immediately, but
        // for a successfully-fired call is only after the promise
        // completes below - not guessing which point libsignal-net's
        // internal take()/into() calls actually run relative to this
        // function returning.
        checkError(signal_register_account_request_destroy(request));
        checkError(signal_registration_account_attributes_destroy(attributes));
        checkError(callErr);
    }

    std::unique_lock<std::mutex> lock(state.mutex);
    state.cv.wait(lock, [&] { return state.done; });
    lock.unlock();

    checkError(signal_register_account_request_destroy(request));
    checkError(signal_registration_account_attributes_destroy(attributes));

    if (state.error) checkError(state.error);

    SignalConstPointerRegisterAccountResponse response{state.result.raw};
    RegisteredAccount result;
    SignalType_FixedArray17_uint8_t aciBinary{};
    checkError(signal_register_account_response_get_identity(&aciBinary, response, kIdentityTypeAci));
    result.aci = serviceIdString(aciBinary);
    SignalType_FixedArray17_uint8_t pniBinary{};
    checkError(signal_register_account_response_get_identity(&pniBinary, response, kIdentityTypePni));
    result.pni = serviceIdString(pniBinary);

    checkError(signal_register_account_response_destroy(state.result));
    return result;
}

} // namespace signal2sip
