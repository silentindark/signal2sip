#include "AuthSocket.h"

#include <libwebsockets.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
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

    void enqueue(Bytes message) {
        {
            std::lock_guard<std::mutex> lock(outgoingMutex);
            outgoing.push_back(std::move(message));
        }
        if (wsi) lws_callback_on_writable(wsi);
        lws_cancel_service(context);
    }

    void sendKeepAlive() {
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
            {
                std::lock_guard<std::mutex> lock(self->connectMutex);
                self->connected = true;
            }
            self->connectCv.notify_all();
            break;
        }
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR: {
            {
                std::lock_guard<std::mutex> lock(self->connectMutex);
                self->connectFailed = true;
                self->connectError = in ? std::string(static_cast<const char*>(in), len) : "connection error";
            }
            self->connectCv.notify_all();
            break;
        }
        case LWS_CALLBACK_CLIENT_CLOSED: {
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

    lws_client_connect_info connectInfo{};
    connectInfo.context = impl_->context;
    connectInfo.address = "chat.signal.org";
    connectInfo.port = 443;
    connectInfo.ssl_connection = LCCSCF_USE_SSL;
    connectInfo.path = "/v1/websocket/";
    connectInfo.host = connectInfo.address;
    connectInfo.origin = connectInfo.address;
    connectInfo.protocol = Impl::kProtocols[0].name;
    connectInfo.pwsi = &impl_->wsi;

    if (!lws_client_connect_via_info(&connectInfo)) {
        throw std::runtime_error("lws_client_connect_via_info failed");
    }

    impl_->serviceThread = std::thread([this] {
        while (!impl_->stopping.load()) {
            lws_service(impl_->context, 50);
        }
    });

    std::unique_lock<std::mutex> lock(impl_->connectMutex);
    bool ok = impl_->connectCv.wait_for(lock, std::chrono::seconds(15),
                                        [this] { return impl_->connected || impl_->connectFailed; });
    if (!ok) throw std::runtime_error("timed out connecting to chat.signal.org");
    if (impl_->connectFailed) throw std::runtime_error("websocket connect failed: " + impl_->connectError);

    impl_->keepAliveThread = std::thread([this] {
        while (!impl_->stopping.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(15));
            if (!impl_->stopping.load()) impl_->sendKeepAlive();
        }
    });
}

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
