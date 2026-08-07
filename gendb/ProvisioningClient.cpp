#include "ProvisioningClient.h"

#include <libwebsockets.h>
#include <qrencode.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>

#include "ProvisioningCipher.h"
#include "Provisioning.pb.h"
#include "WebSocketResources.pb.h"
#include "../signal/FfiUtil.h"
#include "../util/Base64.h"

namespace signal2sip {

namespace {

std::string base64NoPadding(const Bytes& data) {
    std::string s = base64Encode(data);
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

std::string urlEncode(const std::string& in) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : in) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

// Half-block ("small") terminal QR render - two module rows per printed
// text row, same visual density qrcode-terminal's {small:true} produced in
// the Node version. Camera scanning of this is font/terminal-dependent
// (the half-block trick assumes the terminal's character cells are close
// enough to 1:2 width:height that each glyph renders as two roughly-square
// modules - not guaranteed for every font/terminal, and line-wrapping in a
// narrow window silently corrupts the whole pattern) - renderQr() below
// also always writes a real PNG as a dependency-free fallback that sidesteps
// all of that.
//
// Two real scan-failure causes fixed 2026-08-08 after a live report of a
// phone camera refusing to lock onto this: (1) the quiet zone here was only
// 2 modules - the QR spec (ISO/IEC 18004) calls for 4, and most scanners'
// finder-pattern search genuinely relies on that full margin being blank;
// (2) this printed with no explicit colors at all, so it inherited
// whatever the surrounding terminal's colors were - on a dark-themed
// terminal (the common case) that renders as light block glyphs on a dark
// background, the exact inverse of the dark-modules-on-light convention
// scanners are tuned for. Explicit SGR codes force true black-on-white
// here regardless of the terminal's own theme; signal2sip-tui's Screen 5
// does the equivalent at the FTXUI layer for the same reason (raw ANSI
// codes piped through a subprocess don't reach FTXUI's own text styling).
void printQrAscii(const QRcode* qr) {
    int width = qr->width;
    auto dark = [&](int x, int y) -> bool {
        if (x < 0 || y < 0 || x >= width || y >= width) return false;
        return (qr->data[y * width + x] & 1) != 0;
    };
    std::cout << "\x1b[30;107m"; // black-on-bright-white, overriding the terminal's own theme
    // 6-module quiet zone border on every side - past ISO/IEC 18004's
    // 4-module recommended minimum, deliberately generous since each
    // "module" here is only a character cell (coarse compared to a real
    // printed/screen QR), and this was still hard to lock onto with just
    // the spec minimum in a live test.
    for (int y = -6; y < width + 6; y += 2) {
        std::string line;
        for (int x = -6; x < width + 6; x++) {
            bool top = dark(x, y);
            bool bottom = dark(x, y + 1);
            if (top && bottom) {
                line += "█";
            } else if (top) {
                line += "▀";
            } else if (bottom) {
                line += "▄";
            } else {
                line += " ";
            }
        }
        std::cout << line << "\n";
    }
    std::cout << "\x1b[0m"; // reset - don't leak black-on-white into whatever prints next
}

uint32_t crc32Of(const uint8_t* data, size_t len) {
    static uint32_t table[256];
    static bool tableReady = false;
    if (!tableReady) {
        for (uint32_t n = 0; n < 256; n++) {
            uint32_t c = n;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[n] = c;
        }
        tableReady = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

void putBE32(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v >> 24));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v));
}

void writePngChunk(std::vector<uint8_t>& out, const char* type, const std::vector<uint8_t>& data) {
    putBE32(out, static_cast<uint32_t>(data.size()));
    std::vector<uint8_t> typeAndData(type, type + 4);
    typeAndData.insert(typeAndData.end(), data.begin(), data.end());
    out.insert(out.end(), typeAndData.begin(), typeAndData.end());
    putBE32(out, crc32Of(typeAndData.data(), typeAndData.size()));
}

// Wraps `data` as a minimal, valid zlib stream using deflate's "stored"
// (uncompressed) block type - a legal subset of the deflate spec that
// needs no real compression, so PNG's IDAT payload (which must be
// zlib-compressed) can be produced without a zlib/libpng dependency. Fine
// for a small 1-bit QR bitmap.
std::vector<uint8_t> zlibStoreUncompressed(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> out{0x78, 0x01}; // zlib header: deflate, no/low compression
    size_t offset = 0;
    do {
        size_t chunkLen = std::min<size_t>(65535, data.size() - offset);
        bool isLast = (offset + chunkLen) >= data.size();
        out.push_back(isLast ? 1 : 0); // BFINAL | BTYPE=00 (stored), already byte-aligned
        auto len = static_cast<uint16_t>(chunkLen);
        auto nlen = static_cast<uint16_t>(~len);
        out.push_back(static_cast<uint8_t>(len));
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.push_back(static_cast<uint8_t>(nlen));
        out.push_back(static_cast<uint8_t>(nlen >> 8));
        out.insert(out.end(), data.begin() + static_cast<long>(offset), data.begin() + static_cast<long>(offset + chunkLen));
        offset += chunkLen;
    } while (offset < data.size());

    uint32_t a = 1, b = 0;
    for (uint8_t byte : data) {
        a = (a + byte) % 65521;
        b = (b + a) % 65521;
    }
    putBE32(out, (b << 16) | a);
    return out;
}

// 1-bit grayscale PNG, `scale` pixels per QR module plus a 4-module quiet
// zone - a real image sidesteps every terminal-rendering quirk that can
// make printQrAscii()'s output fail to scan (font metrics, line-wrapping,
// color inversion): open it in any image viewer (VS Code can preview a
// PNG directly) and scan it off the screen instead.
void writeQrPng(const QRcode* qr, int scale, const std::string& path) {
    constexpr int kQuietModules = 4;
    int modules = qr->width;
    int size = (modules + kQuietModules * 2) * scale;
    int rowBytes = (size + 7) / 8;

    std::vector<uint8_t> raw;
    raw.reserve(static_cast<size_t>(size) * (1 + rowBytes));
    for (int y = 0; y < size; y++) {
        raw.push_back(0); // filter type: None
        std::vector<uint8_t> row(static_cast<size_t>(rowBytes), 0xFF); // all white (bit=1) by default
        int qy = y / scale - kQuietModules;
        for (int x = 0; x < size; x++) {
            int qx = x / scale - kQuietModules;
            bool dark = qx >= 0 && qx < modules && qy >= 0 && qy < modules &&
                       (qr->data[qy * modules + qx] & 1) != 0;
            if (dark) row[static_cast<size_t>(x / 8)] &= static_cast<uint8_t>(~(0x80 >> (x % 8)));
        }
        raw.insert(raw.end(), row.begin(), row.end());
    }

    std::vector<uint8_t> png{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    std::vector<uint8_t> ihdr;
    putBE32(ihdr, static_cast<uint32_t>(size));
    putBE32(ihdr, static_cast<uint32_t>(size));
    ihdr.push_back(1); // bit depth
    ihdr.push_back(0); // color type: grayscale
    ihdr.push_back(0); // compression method
    ihdr.push_back(0); // filter method
    ihdr.push_back(0); // interlace method
    writePngChunk(png, "IHDR", ihdr);
    writePngChunk(png, "IDAT", zlibStoreUncompressed(raw));
    writePngChunk(png, "IEND", {});

    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("cannot write " + path);
    f.write(reinterpret_cast<const char*>(png.data()), static_cast<std::streamsize>(png.size()));
}

constexpr const char* kQrPngPath = "/tmp/signal2sip-link-qr.png";

void renderQr(const std::string& text) {
    QRcode* qr = QRcode_encodeString(text.c_str(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    if (!qr) {
        std::cout << "[link] (failed to render QR - use the URL above)\n";
        return;
    }
    printQrAscii(qr);
    try {
        writeQrPng(qr, 8, kQrPngPath);
        std::cout << "[link] if the terminal QR above doesn't scan, a PNG was also written to " << kQrPngPath
                  << " on this machine. If this is a headless/remote box, fetch it to view locally, e.g.:\n";
        std::cout << "  scp <user>@<this-host>:" << kQrPngPath << " .\n";
        std::cout << "then open the downloaded file and scan that instead.\n";
    } catch (const std::exception& e) {
        std::cout << "[link] (could not also write " << kQrPngPath << ": " << e.what() << ")\n";
    }
    QRcode_free(qr);
}

} // namespace

struct ProvisioningClient::Impl {
    std::string caCertPath;
    std::string serverHost;
    KeyPair ourKeyPair;

    lws_context* context = nullptr;
    lws* wsi = nullptr;
    std::thread serviceThread;
    std::thread keepAliveThread;
    std::atomic<bool> stopping{false};

    std::mutex connectMutex;
    std::condition_variable connectCv;
    bool connected = false;
    bool connectFailed = false;
    std::string connectError;

    std::mutex outgoingMutex;
    std::deque<Bytes> outgoing;
    Bytes rxBuffer;

    std::mutex resultMutex;
    std::condition_variable resultCv;
    bool gotAddress = false;
    std::optional<ProvisionMessageResult> result;
    std::optional<std::string> failure;

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

    void printLinkUrl(const std::string& address) {
        std::string url =
            "sgnl://linkdevice?uuid=" + urlEncode(address) + "&pub_key=" + urlEncode(base64NoPadding(ourKeyPair.publicKey));
        std::cout << "[link] scan this with the Signal app on your phone (Settings > Linked devices > Link a "
                     "device):\n";
        std::cout << url << "\n";
        renderQr(url);
    }

    void handleIncomingMessage(const Bytes& data) {
        signalservice::WebSocketMessage msg;
        if (!msg.ParseFromArray(data.data(), static_cast<int>(data.size()))) return;
        if (msg.type() != signalservice::WebSocketMessage_Type_REQUEST || !msg.has_request()) return;

        const auto& req = msg.request();

        signalservice::WebSocketMessage ack;
        ack.set_type(signalservice::WebSocketMessage_Type_RESPONSE);
        auto* ackResp = ack.mutable_response();
        ackResp->set_id(req.id());
        ackResp->set_status(200);
        ackResp->set_message("OK");
        std::string serializedAck;
        ack.SerializeToString(&serializedAck);
        enqueue(Bytes(serializedAck.begin(), serializedAck.end()));

        if (req.verb() == "PUT" && req.path() == "/v1/address") {
            signalservice::ProvisioningAddress address;
            if (!address.ParseFromString(req.body())) return;
            {
                std::lock_guard<std::mutex> lock(resultMutex);
                gotAddress = true;
            }
            resultCv.notify_all();
            printLinkUrl(address.address());
            return;
        }

        if (req.verb() == "PUT" && req.path() == "/v1/message") {
            try {
                signalservice::ProvisionEnvelope envelope;
                if (!envelope.ParseFromString(req.body())) throw std::runtime_error("bad ProvisionEnvelope");
                Bytes publicKey(envelope.publickey().begin(), envelope.publickey().end());
                Bytes body(envelope.body().begin(), envelope.body().end());
                Bytes plaintext = decryptProvisionEnvelope(ourKeyPair.privateKey, publicKey, body);

                signalservice::ProvisionMessage pm;
                if (!pm.ParseFromArray(plaintext.data(), static_cast<int>(plaintext.size()))) {
                    throw std::runtime_error("bad ProvisionMessage");
                }

                ProvisionMessageResult r;
                r.e164 = pm.number();
                r.aci = pm.aci();
                r.pni = pm.pni();
                r.aciIdentityKeyPublic.assign(pm.aciidentitykeypublic().begin(), pm.aciidentitykeypublic().end());
                r.aciIdentityKeyPrivate.assign(pm.aciidentitykeyprivate().begin(), pm.aciidentitykeyprivate().end());
                r.pniIdentityKeyPublic.assign(pm.pniidentitykeypublic().begin(), pm.pniidentitykeypublic().end());
                r.pniIdentityKeyPrivate.assign(pm.pniidentitykeyprivate().begin(), pm.pniidentitykeyprivate().end());
                r.provisioningCode = pm.provisioningcode();
                if (pm.has_profilekey()) r.profileKey = Bytes(pm.profilekey().begin(), pm.profilekey().end());
                if (pm.has_accountentropypool()) r.accountEntropyPool = pm.accountentropypool();
                if (pm.has_mediarootbackupkey()) {
                    r.mediaRootBackupKey = Bytes(pm.mediarootbackupkey().begin(), pm.mediarootbackupkey().end());
                }

                std::lock_guard<std::mutex> lock(resultMutex);
                result = std::move(r);
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(resultMutex);
                failure = e.what();
            }
            resultCv.notify_all();
        }
    }
};

const lws_protocols ProvisioningClient::Impl::kProtocols[] = {
    {"signal-provisioning-websocket", &ProvisioningClient::Impl::callback, 0, 65536, 0, nullptr, 0},
    {nullptr, nullptr, 0, 0, 0, nullptr, 0},
};

int ProvisioningClient::Impl::callback(lws* wsi, lws_callback_reasons reason, void* user, void* in, size_t len) {
    auto* self = static_cast<Impl*>(lws_context_user(lws_get_context(wsi)));
    if (!self) return 0;

    switch (reason) {
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
            std::lock_guard<std::mutex> lock(self->resultMutex);
            if (!self->result && !self->failure) self->failure = "socket closed before linking completed";
            self->resultCv.notify_all();
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

ProvisioningClient::ProvisioningClient(std::string caCertPath, std::string serverHost) : impl_(new Impl()) {
    impl_->caCertPath = std::move(caCertPath);
    impl_->serverHost = std::move(serverHost);
    impl_->ourKeyPair = generateKeyPair();
}

ProvisioningClient::~ProvisioningClient() {
    impl_->stopping.store(true);
    if (impl_->context) lws_cancel_service(impl_->context);
    if (impl_->serviceThread.joinable()) impl_->serviceThread.join();
    if (impl_->keepAliveThread.joinable()) impl_->keepAliveThread.join();
    if (impl_->context) {
        lws_context_destroy(impl_->context);
        impl_->context = nullptr;
    }
    delete impl_;
}

ProvisionMessageResult ProvisioningClient::waitForProvisionMessage() {
    // Nothing in this file ever called lws_set_log_level(), so
    // libwebsockets ran at its own built-in default (errors + warnings +
    // NOTICE) - the NOTICE tier is pure connection-lifecycle bookkeeping
    // (context creation, object refcounting, accept-gating) that's noise
    // to an operator watching for the QR/link result, not useful
    // diagnostics. Real failures still surface via LLL_ERR/LLL_WARN and
    // via this function's own std::runtime_error on timeout/failure.
    lws_set_log_level(LLL_ERR | LLL_WARN, nullptr);

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
    connectInfo.address = impl_->serverHost.c_str();
    connectInfo.port = 443;
    connectInfo.ssl_connection = LCCSCF_USE_SSL;
    connectInfo.path = "/v1/websocket/provisioning/";
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

    {
        std::unique_lock<std::mutex> lock(impl_->connectMutex);
        bool ok = impl_->connectCv.wait_for(lock, std::chrono::seconds(15),
                                            [this] { return impl_->connected || impl_->connectFailed; });
        if (!ok) throw std::runtime_error("timed out connecting to provisioning websocket");
        if (impl_->connectFailed) throw std::runtime_error("provisioning websocket connect failed: " + impl_->connectError);
    }

    // LIFESPAN_MS/ADDRESS_TIMEOUT_MS from link-new-device.js, both measured
    // from the moment the socket is actually open (same as its ws.on('open')
    // handler).
    auto opened = std::chrono::steady_clock::now();
    auto addressDeadline = opened + std::chrono::seconds(10);
    auto lifespanDeadline = opened + std::chrono::seconds(90);

    impl_->keepAliveThread = std::thread([this] {
        while (!impl_->stopping.load()) {
            for (int i = 0; i < 300 && !impl_->stopping.load(); i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!impl_->stopping.load()) impl_->sendKeepAlive();
        }
    });

    std::unique_lock<std::mutex> lock(impl_->resultMutex);
    bool gotAddressInTime = impl_->resultCv.wait_until(
        lock, addressDeadline, [this] { return impl_->gotAddress || impl_->result || impl_->failure; });
    if (!gotAddressInTime) throw std::runtime_error("no address received within 10s");
    if (impl_->failure) throw std::runtime_error(*impl_->failure);

    bool done = impl_->resultCv.wait_until(lock, lifespanDeadline,
                                           [this] { return impl_->result.has_value() || impl_->failure.has_value(); });
    if (!done) throw std::runtime_error("lifespan expired with no completed link (90s)");
    if (impl_->failure) throw std::runtime_error(*impl_->failure);
    return *impl_->result;
}

} // namespace signal2sip
