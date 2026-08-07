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

    // True once the WebSocket upgrade has completed and the connection
    // hasn't been closed since - cleared from the background service
    // thread's LWS_CALLBACK_CLIENT_CLOSED handler. Poll this instead of
    // assuming a connect()ed socket stays connected forever; chat.signal.org
    // (or the network path to it) can and does drop the connection with no
    // warning.
    bool isConnected() const;

    // Re-establishes the connection after isConnected() has gone false.
    // Unlike connect(), reuses the existing lws_context and background
    // threads - only redoes the WebSocket handshake itself - so it's safe
    // to call repeatedly from a watchdog loop. Blocks until the handshake
    // completes (or throws on failure/timeout), same as connect().
    void reconnect();

    // True once the most recent connection attempt (or an already-
    // established session) ended because Signal's server rejected or
    // revoked this device's credentials, rather than an ordinary
    // transient network failure: either the WebSocket upgrade itself
    // returned HTTP 401/403, or an established session was closed with
    // close code 4401 ("Reauthentication required" - Signal's real
    // signal for this device having been unlinked/deregistered/had its
    // credentials rotated elsewhere, see WebSocketDisconnectionRequestListener
    // in Signal-Server). Retrying reconnect()/connect() with the same
    // credentials after this is true is futile until the account is
    // re-linked - a caller's watchdog loop should stop retrying and
    // surface this instead of looping forever. Cleared back to false by
    // a subsequent successful connection.
    bool isDeauthorized() const;

    // Client-initiated request (e.g. GET /v2/keys/..., PUT /v1/messages/...).
    // Blocks the calling thread until a response arrives or times out.
    Response request(const std::string& verb, const std::string& path, const Bytes* body = nullptr);

    void close();

private:
    struct Impl;
    Impl* impl_;
};

} // namespace signal2sip
