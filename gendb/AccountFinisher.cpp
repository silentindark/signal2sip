#include "AccountFinisher.h"

#include <ctime>
#include <random>

namespace signal2sip {

int64_t randomRegistrationId() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    std::uniform_int_distribution<int64_t> dist(1, 16383);
    return dist(rng);
}

GeneratedPrekeys generatePrekeys(const Bytes& aciPrivateKey, const Bytes& pniPrivateKey, int64_t keyId) {
    GeneratedPrekeys result;
    result.aciSignedPreKey = generateSignedPreKey(aciPrivateKey, keyId);
    result.pniSignedPreKey = generateSignedPreKey(pniPrivateKey, keyId);
    result.aciKyberPreKey = generateKyberPreKey(aciPrivateKey, keyId);
    result.pniKyberPreKey = generateKyberPreKey(pniPrivateKey, keyId);
    return result;
}

void saveFinishedAccount(Storage& storage, const FinishedAccount& account) {
    AccountRecord record;
    record.e164 = account.e164;
    record.aci = account.aci;
    record.pni = account.pni;
    record.password = account.password;
    record.device_id = account.deviceId;
    record.registration_id = account.registrationId;
    record.pni_registration_id = account.pniRegistrationId;
    record.flow = account.flow;
    record.account_entropy_pool = account.accountEntropyPool;
    record.media_root_backup_key = account.mediaRootBackupKey;
    record.profile_key = account.profileKey;

    int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (account.flow == "standalone") {
        record.registered_at = now;
    } else {
        record.linked_at = now;
    }
    storage.saveAccount(record);

    storage.saveIdentityKeypair("aci",
                                 IdentityKeypairRecord{account.aciIdentity.privateKey, account.aciIdentity.publicKey});
    storage.saveIdentityKeypair("pni",
                                 IdentityKeypairRecord{account.pniIdentity.privateKey, account.pniIdentity.publicKey});

    storage.saveSignedPrekey("aci", account.prekeys.aciSignedPreKey.stored);
    storage.saveSignedPrekey("pni", account.prekeys.pniSignedPreKey.stored);
    storage.saveKyberPrekey("aci", account.prekeys.aciKyberPreKey.stored);
    storage.saveKyberPrekey("pni", account.prekeys.pniKyberPreKey.stored);
}

} // namespace signal2sip
