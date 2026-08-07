#include "AuthSocket.h"

#include <libwebsockets.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>

#include "WebSocketResources.pb.h"
#include "../util/Base64.h"

namespace signal2sip {

struct AuthSocket::Impl {
    std::string username;
    std::string password;
    std::string caCertPath;
    std::function<void(const std::string&, const std::string&, const Bytes&)> onPush;

    lws_context* context = nullptr;
    lws* wsi = nullptr;
    std::thread serviceThread;
    std::atomic<bool> stopping{false};

    std::mutex connectMutex;
    std::condition_variable connectCv;
    bool connected = false;
    bool connectFailed = false;
    std::string connectError;

    // Together, currentWsi/abandonedWsi/isStaleWsi() answer "does this
    // callback belong to the attempt doConnect() is actually still
    // waiting on" - two DIFFERENT staleness signals, both needed, each
    // catching a distinct self-inflicted-flapping scenario found live
    // 2026-08-08 (see git history for the two separate incidents):
    //   - currentWsi: cross-thread-safe mirror of `wsi` below (that
    //     member has its own pre-existing, unrelated data race - written
    //     from doConnect()'s caller thread, read/nulled from the lws
    //     callback thread - not fixed here, out of scope). A callback
    //     whose own wsi parameter doesn't match this is for an attempt a
    //     NEWER doConnect() call has already superseded - e.g. our own
    //     forced-close of an abandoned connection (below) triggers
    //     LWS_CALLBACK_CLIENT_CONNECTION_ERROR for that SAME stale wsi;
    //     without this check that handler would clobber the shared
    //     connectFailed/connectError state a completely different,
    //     still-legitimately-in-progress doConnect() call is waiting on.
    //   - abandonedWsi: set by doConnect() when its local 15s wait times
    //     out (see doConnect()'s own comment) - catches the callback
    //     landing late for the SAME attempt when nothing newer has
    //     started yet, which currentWsi comparison alone can't catch
    //     (currentWsi wouldn't have changed in that window). Using this
    //     late is exactly how a fresh doConnect() succeeding meanwhile
    //     ends up with two live sessions for the same device - Signal's
    //     server then kicks one with a 4409 "Connected elsewhere" close.
    std::atomic<lws*> currentWsi{nullptr};
    std::atomic<lws*> abandonedWsi{nullptr};
    bool isStaleWsi(lws* w) { return w != currentWsi.load() || w == abandonedWsi.load(); }

    // See AuthSocket::isDeauthorized()'s own doc comment. Set from the
    // callback thread in LWS_CALLBACK_CLIENT_CONNECTION_ERROR (upgrade
    // rejected with 401/403) or LWS_CALLBACK_WS_PEER_INITIATED_CLOSE
    // (established session closed with code 4401); cleared on the next
    // LWS_CALLBACK_CLIENT_ESTABLISHED.
    std::atomic<bool> deauthorized{false};

    std::mutex pendingMutex;
    std::condition_variable pendingCv;
    std::map<uint64_t, std::optional<Response>> pendingResponses;
    std::atomic<uint64_t> nextId{1};

    std::mutex outgoingMutex;
    std::deque<Bytes> outgoing;

    Bytes rxBuffer;

    std::thread keepAliveThread;

    static const lws_protocols kProtocols[];

    static int callback(lws* wsi, lws_callback_reasons reason, void* user, void* in, size_t len);

    // Shared by connect() (first-time setup) and reconnect() (after a
    // drop) - both just need a fresh WebSocket handshake against the
    // already-created lws_context. Blocks until the handshake completes
    // or throws on failure/timeout.
    void doConnect() {
        {
            std::lock_guard<std::mutex> lock(connectMutex);
            connected = false;
            connectFailed = false;
            connectError.clear();
        }

        lws_client_connect_info connectInfo{};
        connectInfo.context = context;
        connectInfo.address = "chat.signal.org";
        connectInfo.port = 443;
        connectInfo.ssl_connection = LCCSCF_USE_SSL;
        connectInfo.path = "/v1/websocket/";
        connectInfo.host = connectInfo.address;
        connectInfo.origin = connectInfo.address;
        connectInfo.protocol = kProtocols[0].name;
        connectInfo.pwsi = &wsi;

        if (!lws_client_connect_via_info(&connectInfo)) {
            throw std::runtime_error("lws_client_connect_via_info failed");
        }
        // lws writes the fresh handle into `wsi` synchronously above (only
        // the handshake itself is async) - mirror it into the atomic right
        // away so the callback thread can always tell which attempt is the
        // one anybody's still waiting on, including after this function
        // itself gives up below (see currentWsi's own comment).
        currentWsi = wsi;

        std::unique_lock<std::mutex> lock(connectMutex);
        bool ok = connectCv.wait_for(lock, std::chrono::seconds(15),
                                     [this] { return connected || connectFailed; });
        if (!ok) {
            // Mark this exact attempt abandoned (see abandonedWsi's own
            // comment) before giving up on it - if it lands late, the
            // ESTABLISHED callback needs to recognize and kill it rather
            // than silently starting to use a connection this function
            // already told its caller failed.
            abandonedWsi = wsi;
            throw std::runtime_error("timed out connecting to chat.signal.org");
        }
        if (connectFailed) throw std::runtime_error("websocket connect failed: " + connectError);
    }

    void enqueue(Bytes message) {
        {
            std::lock_guard<std::mutex> lock(outgoingMutex);
            outgoing.push_back(std::move(message));
        }
        if (wsi) lws_callback_on_writable(wsi);
        lws_cancel_service(context);
    }

    void sendKeepAlive() {
        // Skip while disconnected - otherwise these just pile up in
        // `outgoing` for however long the reconnect watchdog takes to
        // notice and fix the underlying drop, then all flush at once the
        // moment reconnect() succeeds.
        {
            std::lock_guard<std::mutex> lock(connectMutex);
            if (!connected) return;
        }
        signalservice::WebSocketMessage msg;
        msg.set_type(signalservice::WebSocketMessage_Type_REQUEST);
        auto* req = msg.mutable_request();
        req->set_id(static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count()));
        req->set_verb("GET");
        req->set_path("/v1/keepalive");
        std::string serialized;
        msg.SerializeToString(&serialized);
        enqueue(Bytes(serialized.begin(), serialized.end()));
    }

    void handleIncomingMessage(const Bytes& data) {
        signalservice::WebSocketMessage msg;
        if (!msg.ParseFromArray(data.data(), static_cast<int>(data.size()))) return;

        if (msg.type() == signalservice::WebSocketMessage_Type_RESPONSE && msg.has_response()) {
            const auto& resp = msg.response();
            uint64_t id = resp.id();
            Response response;
            response.status = resp.status();
            response.body.assign(resp.body().begin(), resp.body().end());
            {
                std::lock_guard<std::mutex> lock(pendingMutex);
                auto it = pendingResponses.find(id);
                if (it != pendingResponses.end()) it->second = response;
            }
            pendingCv.notify_all();
            return;
        }

        if (msg.type() == signalservice::WebSocketMessage_Type_REQUEST && msg.has_request()) {
            const auto& req = msg.request();
            // Ack every server-pushed request immediately, matching the
            // Node prototype's convention (Flow B's provisioning socket,
            // Flow C's message socket).
            signalservice::WebSocketMessage ack;
            ack.set_type(signalservice::WebSocketMessage_Type_RESPONSE);
            auto* ackResp = ack.mutable_response();
            ackResp->set_id(req.id());
            ackResp->set_status(200);
            ackResp->set_message("OK");
            std::string serialized;
            ack.SerializeToString(&serialized);
            enqueue(Bytes(serialized.begin(), serialized.end()));

            if (onPush) {
                Bytes body(req.body().begin(), req.body().end());
                onPush(req.verb(), req.path(), body);
            }
        }
    }
};

const lws_protocols AuthSocket::Impl::kProtocols[] = {
    {"signal-websocket", &AuthSocket::Impl::callback, 0, 65536, 0, nullptr, 0},
    {nullptr, nullptr, 0, 0, 0, nullptr, 0},
};

int AuthSocket::Impl::callback(lws* wsi, lws_callback_reasons reason, void* user, void* in, size_t len) {
    auto* self = static_cast<Impl*>(lws_context_user(lws_get_context(wsi)));
    if (!self) return 0;

    switch (reason) {
        case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER: {
            auto** p = reinterpret_cast<unsigned char**>(in);
            unsigned char* end = (*p) + len;
            std::string credentials = self->username + ":" + self->password;
            std::string auth = "Basic " + base64Encode(Bytes(credentials.begin(), credentials.end()));
            if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char*>("Authorization:"),
                                             reinterpret_cast<const unsigned char*>(auth.data()),
                                             static_cast<int>(auth.size()), p, end)) {
                return -1;
            }
            if (lws_add_http_header_by_name(wsi, reinterpret_cast<const unsigned char*>("X-Signal-Receive-Stories:"),
                                             reinterpret_cast<const unsigned char*>("false"), 5, p, end)) {
                return -1;
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_ESTABLISHED: {
            if (self->isStaleWsi(wsi)) {
                // See isStaleWsi()'s own comment - this attempt is either
                // superseded by a newer one or was already abandoned
                // locally on timeout. Close it instead of marking it
                // connected: using it risks a second live session for
                // this device that Signal's server will notice and kick
                // (4409 "Connected elsewhere"), which was the real cause
                // of a live self-inflicted flapping loop.
                std::cerr << "[authsocket][" << self->username
                           << "] a superseded/timed-out connection attempt established late - closing it instead "
                              "of using it\n";
                return -1;
            }
            {
                std::lock_guard<std::mutex> lock(self->connectMutex);
                self->connected = true;
            }
            self->deauthorized.store(false);
            self->connectCv.notify_all();
            break;
        }
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            if (self->isStaleWsi(wsi)) {
                // This failure belongs to an attempt doConnect() is no
                // longer waiting on - often our own forced-close of a
                // stale connection in LWS_CALLBACK_CLIENT_ESTABLISHED
                // just above, which triggers this callback for that same
                // wsi. Reporting it into the shared connectFailed/
                // connectError state would wake a DIFFERENT, still-
                // legitimately-in-progress doConnect() call with
                // somebody else's failure - live-observed 2026-08-08 as
                // a second self-inflicted flapping loop stacked on top
                // of the first one isStaleWsi() exists to fix.
                std::cerr << "[authsocket][" << self->username
                           << "] connection error on an already-superseded attempt, ignoring\n";
                break;
            }
            // The WebSocket upgrade request itself was rejected - if
            // Signal's server responded with a real HTTP status (rather
            // than the connection failing before any HTTP response, e.g.
            // DNS/TCP/TLS failures), lws_http_client_http_response()
            // still returns it here even though the doc comment says to
            // capture it during LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP -
            // that's for plain HTTP client connections, this is the
            // websocket-upgrade-rejected path, and the wsi is still valid
            // at this point (destroyed only after this callback returns).
            unsigned int httpStatus = lws_http_client_http_response(wsi);
            if (httpStatus == 401 || httpStatus == 403) {
                self->deauthorized.store(true);
            }
            {
                std::lock_guard<std::mutex> lock(self->connectMutex);
                self->connectFailed = true;
                self->connectError = in ? std::string(static_cast<const char*>(in), len) : "connection error";
                if (httpStatus != 0) self->connectError += " (HTTP " + std::to_string(httpStatus) + ")";
            }
            self->connectCv.notify_all();
            break;
        }
        case LWS_CALLBACK_WS_PEER_INITIATED_CLOSE: {
            // The server sent an unsolicited Close frame - in/len are the
            // close code (first 2 bytes, network order) plus optional
            // reason text. 4401 ("Reauthentication required") is Signal's
            // real, purpose-built signal for this device having been
            // unlinked/deregistered/had its credentials rotated
            // elsewhere (see WebSocketDisconnectionRequestListener in
            // Signal-Server) - distinct from an ordinary drop, which
            // carries no close frame or a different code (1000, 1001,
            // etc). Returning 0 (the default) lets lws echo the close and
            // finish tearing the connection down normally; LWS_CALLBACK_
            // CLIENT_CLOSED fires right after this with the actual
            // teardown.
            if (in && len >= 2) {
                const auto* bytes = static_cast<const unsigned char*>(in);
                uint16_t code = (static_cast<uint16_t>(bytes[0]) << 8) | bytes[1];
                std::string reason(reinterpret_cast<const char*>(bytes) + 2, len - 2);
                // Found live 2026-08-07: this was silently discarding the
                // close code/reason for every case except 4401 - real
                // diagnostic gap when a connection is flapping for an
                // unknown server-side reason. Logged unconditionally now,
                // not just on the deauthorization path.
                std::cerr << "[authsocket][" << self->username << "] peer-initiated close, code=" << code
                           << (reason.empty() ? "" : (" reason=" + reason)) << "\n";
                if (code == 4401) self->deauthorized.store(true);
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_CLOSED: {
            // Diagnostic pair with the peer-initiated-close log above: if
            // THIS fires with no preceding "peer-initiated close" line for
            // the same account, the connection died without a WebSocket
            // close frame at all (TCP reset, TLS-layer failure, timeout) -
            // a materially different failure mode than the server
            // cleanly closing it, worth telling apart when chasing a
            // flapping connection.
            bool stale = self->isStaleWsi(wsi);
            std::cerr << "[authsocket][" << self->username << "] connection closed (teardown)"
                       << (stale ? " [already-superseded attempt, ignoring]" : "") << "\n";
            if (stale) {
                // Not the attempt anyone's waiting on (see isStaleWsi()'s
                // own comment) - skip touching connected/pendingResponses
                // entirely, those belong to whatever connection actually
                // IS current right now, not this dead one.
                break;
            }
            {
                std::lock_guard<std::mutex> lock(self->connectMutex);
                self->connected = false;
            }
            self->connectCv.notify_all();
            // wsi is about to be invalidated by libwebsockets - null it out
            // so enqueue() (called from arbitrary threads, e.g. the
            // keepalive thread) stops handing it to lws_callback_on_writable()
            // once this handshake is gone. The next reconnect() attempt
            // gives us a fresh one via connectInfo.pwsi.
            self->wsi = nullptr;
            self->currentWsi = nullptr;
            {
                std::lock_guard<std::mutex> lock(self->pendingMutex);
                for (auto& [id, response] : self->pendingResponses) {
                    if (!response) response = Response{0, {}};
                }
            }
            self->pendingCv.notify_all();
            break;
        }
        case LWS_CALLBACK_CLIENT_RECEIVE: {
            const auto* bytes = static_cast<const uint8_t*>(in);
            self->rxBuffer.insert(self->rxBuffer.end(), bytes, bytes + len);
            if (lws_is_final_fragment(wsi)) {
                self->handleIncomingMessage(self->rxBuffer);
                self->rxBuffer.clear();
            }
            break;
        }
        case LWS_CALLBACK_CLIENT_WRITEABLE: {
            Bytes message;
            {
                std::lock_guard<std::mutex> lock(self->outgoingMutex);
                if (self->outgoing.empty()) break;
                message = std::move(self->outgoing.front());
                self->outgoing.pop_front();
            }
            std::vector<uint8_t> buffer(LWS_PRE + message.size());
            std::memcpy(buffer.data() + LWS_PRE, message.data(), message.size());
            lws_write(wsi, buffer.data() + LWS_PRE, message.size(), LWS_WRITE_BINARY);
            {
                std::lock_guard<std::mutex> lock(self->outgoingMutex);
                if (!self->outgoing.empty()) lws_callback_on_writable(wsi);
            }
            break;
        }
        default:
            break;
    }
    return 0;
}

AuthSocket::AuthSocket(std::string username, std::string password, std::string caCertPath,
                       std::function<void(const std::string&, const std::string&, const Bytes&)> onPush)
    : impl_(new Impl()) {
    impl_->username = std::move(username);
    impl_->password = std::move(password);
    impl_->caCertPath = std::move(caCertPath);
    impl_->onPush = std::move(onPush);
}

AuthSocket::~AuthSocket() {
    close();
    delete impl_;
}

void AuthSocket::connect() {
    lws_context_creation_info info{};
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = Impl::kProtocols;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.client_ssl_ca_filepath = impl_->caCertPath.c_str();
    info.user = impl_;

    impl_->context = lws_create_context(&info);
    if (!impl_->context) throw std::runtime_error("lws_create_context failed");

    impl_->serviceThread = std::thread([this] {
        while (!impl_->stopping.load()) {
            lws_service(impl_->context, 50);
        }
    });

    impl_->doConnect();

    impl_->keepAliveThread = std::thread([this] {
        while (!impl_->stopping.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            if (!impl_->stopping.load()) impl_->sendKeepAlive();
        }
    });
}

bool AuthSocket::isConnected() const {
    std::lock_guard<std::mutex> lock(impl_->connectMutex);
    return impl_->connected;
}

void AuthSocket::reconnect() { impl_->doConnect(); }

bool AuthSocket::isDeauthorized() const { return impl_->deauthorized.load(); }

AuthSocket::Response AuthSocket::request(const std::string& verb, const std::string& path, const Bytes* body) {
    uint64_t id = impl_->nextId.fetch_add(1);

    signalservice::WebSocketMessage msg;
    msg.set_type(signalservice::WebSocketMessage_Type_REQUEST);
    auto* req = msg.mutable_request();
    req->set_id(id);
    req->set_verb(verb);
    req->set_path(path);
    if (body) {
        req->set_body(body->data(), body->size());
        req->add_headers("content-type:application/json");
    }
    std::string serialized;
    msg.SerializeToString(&serialized);

    {
        std::lock_guard<std::mutex> lock(impl_->pendingMutex);
        impl_->pendingResponses[id] = std::nullopt;
    }
    impl_->enqueue(Bytes(serialized.begin(), serialized.end()));

    std::unique_lock<std::mutex> lock(impl_->pendingMutex);
    bool ok = impl_->pendingCv.wait_for(lock, std::chrono::seconds(30), [this, id] {
        auto it = impl_->pendingResponses.find(id);
        return it != impl_->pendingResponses.end() && it->second.has_value();
    });
    Response response = ok ? *impl_->pendingResponses[id] : Response{0, {}};
    impl_->pendingResponses.erase(id);
    lock.unlock();

    if (!ok) throw std::runtime_error(verb + " " + path + " timed out waiting for a response");
    return response;
}

void AuthSocket::close() {
    if (impl_->stopping.exchange(true)) return;
    if (impl_->context) lws_cancel_service(impl_->context);
    if (impl_->serviceThread.joinable()) impl_->serviceThread.join();
    if (impl_->keepAliveThread.joinable()) impl_->keepAliveThread.join();
    if (impl_->context) {
        lws_context_destroy(impl_->context);
        impl_->context = nullptr;
    }
}

} // namespace signal2sip
