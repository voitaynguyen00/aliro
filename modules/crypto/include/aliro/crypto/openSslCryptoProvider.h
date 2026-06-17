#pragma once

#include "aliro/crypto/iCryptoProvider.h"

namespace aliro {

/// ICryptoProvider implementation backed by OpenSSL 3.x.
class OpenSslCryptoProvider : public ICryptoProvider {
public:
    OpenSslCryptoProvider() = default;
    ~OpenSslCryptoProvider() override = default;

    Result<EcKeyPair> generateKeyPair() override;
    Result<Bytes> ecdhCompute(const EcPrivateKey& priv, const EcPublicKey& peerPub) override;
    Result<Signature> sign(ByteView data, const EcPrivateKey& key) override;
    Result<bool> verify(ByteView data, const Signature& sig, const EcPublicKey& key) override;
    Result<Bytes> aesGcmEncrypt(ByteView plaintext, const SessionKey& key, ByteView nonce,
                                ByteView aad) override;
    Result<Bytes> aesGcmDecrypt(ByteView ciphertext, const SessionKey& key, ByteView nonce,
                                ByteView aad) override;
    Result<Bytes> hkdfDerive(ByteView ikm, ByteView salt, ByteView info, size_t outputLen) override;
    Result<Bytes> randomBytes(size_t n) override;
};

}  // namespace aliro
