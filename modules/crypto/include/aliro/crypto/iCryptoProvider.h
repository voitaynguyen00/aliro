#pragma once

#include <cstddef>

#include "aliro/crypto/keyTypes.h"

namespace aliro {

/// Pluggable cryptographic operations required by the Aliro protocol.
class ICryptoProvider {
public:
    virtual ~ICryptoProvider() = default;

    /// Generate a fresh P-256 key pair.
    virtual Result<EcKeyPair> generateKeyPair() = 0;

    /// ECDH: compute shared secret (raw 32-byte X-coordinate).
    virtual Result<Bytes> ecdhCompute(const EcPrivateKey& priv, const EcPublicKey& peerPub) = 0;

    /// ECDSA P-256 / SHA-256 sign. Returns raw r||s (64 bytes).
    virtual Result<Signature> sign(ByteView data, const EcPrivateKey& key) = 0;

    /// ECDSA P-256 / SHA-256 verify. Returns true on valid signature.
    virtual Result<bool> verify(ByteView data, const Signature& sig, const EcPublicKey& key) = 0;

    /// AES-128-GCM encrypt. Returns ciphertext || 16-byte tag.
    virtual Result<Bytes> aesGcmEncrypt(ByteView plaintext, const SessionKey& key, ByteView nonce,
                                        ByteView aad) = 0;

    /// AES-128-GCM decrypt and verify tag. Returns plaintext.
    virtual Result<Bytes> aesGcmDecrypt(ByteView ciphertext, const SessionKey& key, ByteView nonce,
                                        ByteView aad) = 0;

    /// HKDF-SHA-256 key derivation.
    virtual Result<Bytes> hkdfDerive(ByteView ikm, ByteView salt, ByteView info,
                                     size_t outputLen) = 0;

    /// Generate cryptographically secure random bytes.
    virtual Result<Bytes> randomBytes(size_t n) = 0;
};

}  // namespace aliro
