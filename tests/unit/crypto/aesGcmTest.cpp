#include <gtest/gtest.h>

#include "aliro/crypto/openSslCryptoProvider.h"

using namespace aliro;

class AesGcmTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;
};

// NIST SP 800-38D Test Case 1: K=all-zeros, IV=all-zeros, P=empty, A=empty
// Expected tag: 58e2fccefa7e3061367f1d57a4e7455a
TEST_F(AesGcmTest, nistTestCase1_emptyPlaintext) {
    SessionKey key{Bytes(16, 0x00)};
    Bytes nonce(12, 0x00);
    Bytes plaintext;
    Bytes aad;

    auto result = mCrypto.aesGcmEncrypt(plaintext, key, nonce, aad);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 16u);

    Bytes expectedTag = {0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
                         0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a};
    EXPECT_EQ(*result, expectedTag);
}

TEST_F(AesGcmTest, encryptDecryptRoundTrip) {
    SessionKey key{Bytes(16, 0xAB)};
    Bytes nonce(12, 0xCD);
    Bytes plaintext = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    Bytes aad = {0xDE, 0xAD};

    auto encrypted = mCrypto.aesGcmEncrypt(plaintext, key, nonce, aad);
    ASSERT_TRUE(encrypted.has_value());
    EXPECT_EQ(encrypted->size(), plaintext.size() + 16u);

    auto decrypted = mCrypto.aesGcmDecrypt(*encrypted, key, nonce, aad);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(*decrypted, plaintext);
}

TEST_F(AesGcmTest, decrypt_wrongTag_returnsError) {
    SessionKey key{Bytes(16, 0x01)};
    Bytes nonce(12, 0x02);
    Bytes plaintext = {0xAA, 0xBB, 0xCC};
    Bytes aad;

    auto encrypted = mCrypto.aesGcmEncrypt(plaintext, key, nonce, aad);
    ASSERT_TRUE(encrypted.has_value());

    encrypted->back() ^= 0xFF;

    auto decrypted = mCrypto.aesGcmDecrypt(*encrypted, key, nonce, aad);
    EXPECT_FALSE(decrypted.has_value());
}

TEST_F(AesGcmTest, decrypt_wrongAad_returnsError) {
    SessionKey key{Bytes(16, 0x01)};
    Bytes nonce(12, 0x02);
    Bytes plaintext = {0xAA, 0xBB};
    Bytes aad = {0x11};

    auto encrypted = mCrypto.aesGcmEncrypt(plaintext, key, nonce, aad);
    ASSERT_TRUE(encrypted.has_value());

    Bytes wrongAad = {0x22};
    auto decrypted = mCrypto.aesGcmDecrypt(*encrypted, key, nonce, wrongAad);
    EXPECT_FALSE(decrypted.has_value());
}
