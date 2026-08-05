// Throwaway isolation test for the "Call N media 0: Disabled due to no
// active codec" bug found live 08-04 bridging a real incoming Signal call
// through signal2sip-daemon's shared-UDP-transport SIP leg. Reproduces
// ONLY the SIP side (no Signal/RingRTC at all) - mirrors main.cpp's
// ensureSharedEndpoint()/setupAccount() SIP setup exactly, then places a
// bridge-style outbound call, so this can be iterated on quickly without
// needing a real phone call each time.
//
// usage: sip_bridge_codec_test <sip_host> <sip_extension> <sip_password> <dest>

#include <iostream>
#include <thread>
#include <chrono>

#include <pjsua2.hpp>

using namespace pj;

namespace {

class TestAccount : public Account {
public:
    std::atomic<bool> registered{false};
    void onRegState(OnRegStateParam&) override {
        AccountInfo ai = getInfo();
        std::cout << "[test] reg state active=" << ai.regIsActive << "\n";
        registered = ai.regIsActive;
    }
};

class TestCall : public Call {
public:
    explicit TestCall(Account& acc) : Call(acc) {}
    void onCallState(OnCallStateParam&) override {
        CallInfo ci = getInfo();
        std::cout << "[test] call state=" << ci.stateText << " (" << ci.state << ")\n";
        if (ci.state == PJSIP_INV_STATE_DISCONNECTED) disconnected = true;
    }
    std::atomic<bool> disconnected{false};
};

}  // namespace

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "usage: sip_bridge_codec_test <sip_host> <sip_extension> <sip_password> <dest>\n";
        return 2;
    }
    std::string host = argv[1], user = argv[2], password = argv[3], dest = argv[4];

    Endpoint ep;
    try {
        ep.libCreate();

        // Matches main.cpp's ensureSharedEndpoint() exactly.
        EpConfig epConfig;
        epConfig.medConfig.ecTailLen = 0;
        epConfig.medConfig.noVad = true;
        epConfig.medConfig.audioFramePtime = 10;
        epConfig.medConfig.ptime = 10;
        epConfig.medConfig.clockRate = 48000;
        ep.libInit(epConfig);
        ep.audDevManager().setNullDev();

        for (const auto& codec : ep.codecEnum2()) {
            ep.codecSetPriority(codec.codecId, codec.codecId == "L16/48000/1" ? 255 : 0);
        }

        TransportConfig tcfg;
        tcfg.port = 5099;  // distinct from the real daemon's 5063
        ep.transportCreate(PJSIP_TRANSPORT_UDP, tcfg);
        ep.libStart();

        std::cout << "[test] codecs after priority pass:\n";
        for (const auto& codec : ep.codecEnum2()) {
            std::cout << "  " << codec.codecId << " priority=" << (int)codec.priority << "\n";
        }

        // Matches main.cpp's setupAccount() exactly for a plain-UDP,
        // sip_srtp=disabled account (signal2sip-123456789002's real config).
        AccountConfig acfg;
        acfg.idUri = "sip:" + user + "@" + host;
        acfg.regConfig.registrarUri = "sip:" + host;
        AuthCredInfo cred("digest", "*", user, 0, password);
        acfg.sipConfig.authCreds.push_back(cred);
        acfg.mediaConfig.srtpSecureSignaling = 0;

        TestAccount acc;
        acc.create(acfg);

        std::cout << "[test] waiting for SIP registration...\n";
        for (int i = 0; i < 100 && !acc.registered.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (!acc.registered.load()) {
            std::cerr << "[test] FAIL: SIP registration did not complete in time\n";
            return 1;
        }
        std::cout << "[test] PASS: SIP registered\n";

        std::string destUri = "sip:" + dest + "@" + host;
        std::cout << "[test][sip] placing bridge call to " << destUri << "\n";
        auto* call = new TestCall(acc);
        CallOpParam prm(true);
        prm.opt.audioCount = 1;
        prm.opt.videoCount = 0;
        try {
            call->makeCall(destUri, prm);
        } catch (Error& err) {
            std::cerr << "[test] FAIL: makeCall: " << err.info() << "\n";
        }

        for (int i = 0; i < 100 && !call->disconnected.load(); i++) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        ep.libDestroy();
    } catch (Error& err) {
        std::cerr << "[test] FAIL: " << err.info() << "\n";
        return 1;
    }
    return 0;
}
