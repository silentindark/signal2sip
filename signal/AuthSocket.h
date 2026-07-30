#pragma once

// Authenticated request/response client over Signal's persistent WebSocket
// (wss://chat.signal.org/v1/websocket/), C++ port of layer1/authSocket.js.
// Some Signal-Server endpoints (e.g. PUT /v2/keys) only exist as an
// HTTP-over-websocket call - there is no plain REST equivalent - so this is
// a required transport, not a convenience wrapper.

#include <cstdint>
#include <functional>
#include <string>

#include "../storage/Storage.h"

struct lws_context;
struct lws;

namespace signal2sip {

class AuthSocket {
public:
    struct Response {
        uint32_t status = 0;
        Bytes body;
    };

    // onPush is invoked (from the socket's background thread) for every
    // server-pushed request (incoming envelopes, queue-empty, etc.) -
    // matches AuthSocket's onPush in the Node prototype. This class acks
    // every push automatically before invoking the callback, same as
    // there.
    AuthSocket(std::string username, std::string password, std::string caCertPath,
               std::function<void(const std::string& verb, const std::string& path, const Bytes& body)> onPush);
    ~AuthSocket();

    AuthSocket(const AuthSocket&) = delete;
    AuthSocket& operator=(const AuthSocket&) = delete;

    // Connects and blocks until the WebSocket upgrade completes (or throws
    // on failure/timeout).
    void connect();

    // Client-initiated request (e.g. GET /v2/keys/..., PUT /v1/messages/...).
    // Blocks the calling thread until a response arrives or times out.
    Response request(const std::string& verb, const std::string& path, const Bytes* body = nullptr);

    void close();

private:
    struct Impl;
    Impl* impl_;
};

} // namespace signal2sip
