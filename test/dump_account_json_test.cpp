// Throwaway helper: dumps an existing account's stored aci/password/e164/
// deviceId as JSON, matching what refresh_prekeys_test.cpp/cdsi_lookup_test.cpp
// expect on their command line - so those can be pointed at a real account
// already in the shared SQLCipher DB without hand-copying credentials out.
//
// usage: dump_account_json_test <db_path> <db_key> <account_name>

#include <iostream>

#include <nlohmann/json.hpp>

#include "../storage/Storage.h"

using namespace signal2sip;
using json = nlohmann::json;

int main(int argc, char** argv) {
    if (argc != 4) {
        std::cerr << "usage: dump_account_json_test <db_path> <db_key> <account_name>\n";
        return 2;
    }
    Storage storage(argv[1], argv[2], argv[3]);
    AccountRecord account = storage.loadAccount();

    json out = {
        {"e164", account.e164},
        {"aci", account.aci},
        {"deviceId", account.device_id},
        {"password", account.password},
    };
    std::cout << out.dump() << "\n";
    return 0;
}
