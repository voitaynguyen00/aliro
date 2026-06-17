#pragma once

#include "aliro/core/types.h"
#include "aliro/crypto/iCryptoProvider.h"

namespace aliro {

/// Counter-based AES-128-GCM secure channel using a shared session key.
///
/// Each endpoint maintains independent send and receive counters, so both
/// sides can share the same 16-byte session key without nonce collision.
///
/// Nonce format (12 bytes): 4-byte big-endian counter || 8 zero bytes.
/// Ciphertext format:       plaintext bytes encrypted || 16-byte GCM tag.
class SecureChannel {
public:
    SecureChannel(ICryptoProvider& crypto, ByteView sessionKey);

    /// Encrypt plaintext. Returns ciphertext||tag (increases send counter).
    Result<Bytes> encrypt(ByteView plaintext, ByteView aad = {});

    /// Decrypt ciphertext||tag. Returns plaintext (increases recv counter).
    /// Returns CRYPTO_FAILURE if authentication fails.
    Result<Bytes> decrypt(ByteView ciphertext, ByteView aad = {});

private:
    ICryptoProvider& mCrypto;
    SessionKey mKey;
    uint32_t mSendCounter{0};
    uint32_t mRecvCounter{0};

    static Bytes makeNonce(uint32_t counter);
};

}  // namespace aliro
