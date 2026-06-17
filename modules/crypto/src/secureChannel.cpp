#include "aliro/crypto/secureChannel.h"

namespace aliro {

SecureChannel::SecureChannel(ICryptoProvider& crypto, ByteView sessionKey)
    : mCrypto(crypto)
    , mKey(SessionKey{Bytes(sessionKey.begin(), sessionKey.end())})
{}

Bytes SecureChannel::makeNonce(uint32_t counter) {
    Bytes nonce(12, 0x00);
    nonce[0] = static_cast<uint8_t>((counter >> 24) & 0xFF);
    nonce[1] = static_cast<uint8_t>((counter >> 16) & 0xFF);
    nonce[2] = static_cast<uint8_t>((counter >>  8) & 0xFF);
    nonce[3] = static_cast<uint8_t>( counter        & 0xFF);
    return nonce;
}

Result<Bytes> SecureChannel::encrypt(ByteView plaintext, ByteView aad) {
    auto nonce  = makeNonce(mSendCounter);
    auto result = mCrypto.aesGcmEncrypt(plaintext, mKey, nonce, aad);
    if (result) ++mSendCounter;
    return result;
}

Result<Bytes> SecureChannel::decrypt(ByteView ciphertext, ByteView aad) {
    auto nonce  = makeNonce(mRecvCounter);
    auto result = mCrypto.aesGcmDecrypt(ciphertext, mKey, nonce, aad);
    if (result) ++mRecvCounter;
    return result;
}

} // namespace aliro
