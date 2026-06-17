#pragma once

#include "aliro/crypto/iCryptoProvider.h"
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

namespace aliro {

/// ICryptoProvider implementation backed by MbedTLS 3.x.
/// Suitable for embedded targets that cannot use OpenSSL.
class MbedTlsCryptoProvider final : public ICryptoProvider {
public:
    MbedTlsCryptoProvider();
    ~MbedTlsCryptoProvider() override;

    Result<EcKeyPair> generateKeyPair() override;
    Result<Bytes>     ecdhCompute(const EcPrivateKey& priv,
                                  const EcPublicKey&  peerPub) override;
    Result<Signature> sign(ByteView data, const EcPrivateKey& key) override;
    Result<bool>      verify(ByteView data, const Signature& sig,
                             const EcPublicKey& key) override;
    Result<Bytes>     aesGcmEncrypt(ByteView plaintext, const SessionKey& key,
                                    ByteView nonce, ByteView aad) override;
    Result<Bytes>     aesGcmDecrypt(ByteView ciphertext, const SessionKey& key,
                                    ByteView nonce, ByteView aad) override;
    Result<Bytes>     hkdfDerive(ByteView ikm, ByteView salt,
                                 ByteView info, size_t outputLen) override;
    Result<Bytes>     randomBytes(size_t n) override;

private:
    mbedtls_entropy_context  mEntropy;
    mbedtls_ctr_drbg_context mCtrDrbg;
    bool                     mInitialized{false};
};

} // namespace aliro
