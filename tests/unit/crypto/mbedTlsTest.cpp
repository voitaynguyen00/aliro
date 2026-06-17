#include <gtest/gtest.h>

#include "aliro/core/protocol.h"
#include "aliro/crypto/mbedTlsCryptoProvider.h"
#include "aliro/crypto/openSslCryptoProvider.h"

using namespace aliro;

class MbedTlsCryptoTest : public ::testing::Test {
protected:
    MbedTlsCryptoProvider mCrypto;
};

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------
TEST_F(MbedTlsCryptoTest, generateKeyPair_pubKeyIs65Bytes) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->pub.data.size(), protocol::kEcPublicKeySize);
    EXPECT_EQ(kp->pub.data[0], 0x04);
}

TEST_F(MbedTlsCryptoTest, generateKeyPair_privKeyIs32Bytes) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->priv.data.size(), protocol::kEcPrivateKeySize);
}

TEST_F(MbedTlsCryptoTest, generateKeyPair_twoCallsProduceDifferentKeys) {
    auto kp1 = mCrypto.generateKeyPair();
    auto kp2 = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp1.has_value() && kp2.has_value());
    EXPECT_NE(kp1->pub.data, kp2->pub.data);
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------
TEST_F(MbedTlsCryptoTest, sign_producesRawSigOf64Bytes) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    Bytes msg = {0x01, 0x02, 0x03, 0x04};
    auto sig = mCrypto.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->data.size(), 64u);
}

TEST_F(MbedTlsCryptoTest, verify_validSignatureReturnsTrue) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    auto sig = mCrypto.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());
    auto ok = mCrypto.verify(msg, *sig, kp->pub);
    ASSERT_TRUE(ok.has_value());
    EXPECT_TRUE(*ok);
}

TEST_F(MbedTlsCryptoTest, verify_wrongMessageReturnsFalse) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes other = {0xCA, 0xFE, 0xBA, 0xBE};
    auto sig = mCrypto.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());
    auto ok = mCrypto.verify(other, *sig, kp->pub);
    ASSERT_TRUE(ok.has_value());
    EXPECT_FALSE(*ok);
}

TEST_F(MbedTlsCryptoTest, verify_wrongKeyReturnsFalse) {
    auto kpA = mCrypto.generateKeyPair();
    auto kpB = mCrypto.generateKeyPair();
    ASSERT_TRUE(kpA.has_value() && kpB.has_value());
    Bytes msg = {0x11, 0x22, 0x33};
    auto sig = mCrypto.sign(msg, kpA->priv);
    ASSERT_TRUE(sig.has_value());
    auto ok = mCrypto.verify(msg, *sig, kpB->pub);
    ASSERT_TRUE(ok.has_value());
    EXPECT_FALSE(*ok);
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------
TEST_F(MbedTlsCryptoTest, ecdhCompute_symmetricSecret) {
    auto kpA = mCrypto.generateKeyPair();
    auto kpB = mCrypto.generateKeyPair();
    ASSERT_TRUE(kpA.has_value() && kpB.has_value());

    auto secretAB = mCrypto.ecdhCompute(kpA->priv, kpB->pub);
    auto secretBA = mCrypto.ecdhCompute(kpB->priv, kpA->pub);
    ASSERT_TRUE(secretAB.has_value() && secretBA.has_value());
    EXPECT_EQ(*secretAB, *secretBA);
}

TEST_F(MbedTlsCryptoTest, ecdhCompute_producesNonZeroSecret) {
    auto kpA = mCrypto.generateKeyPair();
    auto kpB = mCrypto.generateKeyPair();
    ASSERT_TRUE(kpA.has_value() && kpB.has_value());

    auto secret = mCrypto.ecdhCompute(kpA->priv, kpB->pub);
    ASSERT_TRUE(secret.has_value());
    EXPECT_EQ(secret->size(), 32u);
    EXPECT_FALSE(std::all_of(secret->begin(), secret->end(), [](uint8_t b) { return b == 0; }));
}

// ---------------------------------------------------------------------------
// AES-GCM
// ---------------------------------------------------------------------------
TEST_F(MbedTlsCryptoTest, aesGcm_encryptDecryptRoundTrip) {
    SessionKey key{Bytes(16, 0xAB)};
    Bytes nonce(12, 0x01);
    Bytes plaintext = {1, 2, 3, 4, 5, 6, 7, 8};

    auto ct = mCrypto.aesGcmEncrypt(plaintext, key, nonce, {});
    ASSERT_TRUE(ct.has_value());
    EXPECT_EQ(ct->size(), plaintext.size() + 16);

    auto pt = mCrypto.aesGcmDecrypt(*ct, key, nonce, {});
    ASSERT_TRUE(pt.has_value());
    EXPECT_EQ(*pt, plaintext);
}

TEST_F(MbedTlsCryptoTest, aesGcm_emptyPlaintext_roundTrip) {
    SessionKey key{Bytes(16, 0x00)};
    Bytes nonce(12, 0x00);

    auto ct = mCrypto.aesGcmEncrypt({}, key, nonce, {});
    ASSERT_TRUE(ct.has_value());
    EXPECT_EQ(ct->size(), 16u);  // only tag

    auto pt = mCrypto.aesGcmDecrypt(*ct, key, nonce, {});
    ASSERT_TRUE(pt.has_value());
    EXPECT_TRUE(pt->empty());
}

TEST_F(MbedTlsCryptoTest, aesGcm_withAad_roundTrip) {
    SessionKey key{Bytes(16, 0xCC)};
    Bytes nonce(12, 0x02);
    Bytes plaintext = {0xDE, 0xAD};
    Bytes aad = {0xFF, 0xFE};

    auto ct = mCrypto.aesGcmEncrypt(plaintext, key, nonce, aad);
    ASSERT_TRUE(ct.has_value());

    auto pt = mCrypto.aesGcmDecrypt(*ct, key, nonce, aad);
    ASSERT_TRUE(pt.has_value());
    EXPECT_EQ(*pt, plaintext);
}

TEST_F(MbedTlsCryptoTest, aesGcm_corruptedCiphertext_returnsError) {
    SessionKey key{Bytes(16, 0xAB)};
    Bytes nonce(12, 0x01);
    Bytes plaintext = {1, 2, 3, 4};

    auto ct = mCrypto.aesGcmEncrypt(plaintext, key, nonce, {});
    ASSERT_TRUE(ct.has_value());
    ct->front() ^= 0xFF;  // corrupt

    auto pt = mCrypto.aesGcmDecrypt(*ct, key, nonce, {});
    EXPECT_FALSE(pt.has_value());
}

TEST_F(MbedTlsCryptoTest, aesGcm_aadMismatch_returnsError) {
    SessionKey key{Bytes(16, 0xAB)};
    Bytes nonce(12, 0x01);
    Bytes plaintext = {1, 2, 3, 4};
    Bytes aadEnc = {0xAA};
    Bytes aadDec = {0xBB};

    auto ct = mCrypto.aesGcmEncrypt(plaintext, key, nonce, aadEnc);
    ASSERT_TRUE(ct.has_value());

    auto pt = mCrypto.aesGcmDecrypt(*ct, key, nonce, aadDec);
    EXPECT_FALSE(pt.has_value());
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------
TEST_F(MbedTlsCryptoTest, hkdfDerive_producesCorrectLength) {
    Bytes ikm = {0x01, 0x02, 0x03};
    Bytes salt = {0x04, 0x05};
    Bytes info = {0x06};

    auto key = mCrypto.hkdfDerive(ikm, salt, info, 16);
    ASSERT_TRUE(key.has_value());
    EXPECT_EQ(key->size(), 16u);
}

TEST_F(MbedTlsCryptoTest, hkdfDerive_differentInputs_differentOutputs) {
    Bytes ikm = {0x01, 0x02};
    Bytes salt = {0x03};
    Bytes info = {0x04};

    auto key1 = mCrypto.hkdfDerive(ikm, salt, info, 16);
    Bytes ikm2 = {0xFF, 0xFE};
    auto key2 = mCrypto.hkdfDerive(ikm2, salt, info, 16);
    ASSERT_TRUE(key1.has_value() && key2.has_value());
    EXPECT_NE(*key1, *key2);
}

// ---------------------------------------------------------------------------
// Random
// ---------------------------------------------------------------------------
TEST_F(MbedTlsCryptoTest, randomBytes_producesCorrectLength) {
    auto r = mCrypto.randomBytes(32);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->size(), 32u);
}

TEST_F(MbedTlsCryptoTest, randomBytes_twoCalls_differentResults) {
    auto r1 = mCrypto.randomBytes(16);
    auto r2 = mCrypto.randomBytes(16);
    ASSERT_TRUE(r1.has_value() && r2.has_value());
    EXPECT_NE(*r1, *r2);
}

// ---------------------------------------------------------------------------
// Cross-provider interoperability
// ---------------------------------------------------------------------------
TEST(MbedTlsInteropTest, opensslSign_mbedtlsVerify) {
    OpenSslCryptoProvider openssl;
    MbedTlsCryptoProvider mbedtls;

    auto kp = openssl.generateKeyPair();
    ASSERT_TRUE(kp.has_value());

    Bytes msg = {0xCA, 0xFE, 0xBA, 0xBE};
    auto sig = openssl.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());

    auto ok = mbedtls.verify(msg, *sig, kp->pub);
    ASSERT_TRUE(ok.has_value());
    EXPECT_TRUE(*ok);
}

TEST(MbedTlsInteropTest, mbedtlsSign_opensslVerify) {
    MbedTlsCryptoProvider mbedtls;
    OpenSslCryptoProvider openssl;

    auto kp = mbedtls.generateKeyPair();
    ASSERT_TRUE(kp.has_value());

    Bytes msg = {0x11, 0x22, 0x33, 0x44};
    auto sig = mbedtls.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());

    auto ok = openssl.verify(msg, *sig, kp->pub);
    ASSERT_TRUE(ok.has_value());
    EXPECT_TRUE(*ok);
}

TEST(MbedTlsInteropTest, opensslEcdh_mbedtlsEcdh_sameSecret) {
    OpenSslCryptoProvider openssl;
    MbedTlsCryptoProvider mbedtls;

    auto kpA = openssl.generateKeyPair();
    auto kpB = mbedtls.generateKeyPair();
    ASSERT_TRUE(kpA.has_value() && kpB.has_value());

    auto secretOpenssl = openssl.ecdhCompute(kpA->priv, kpB->pub);
    auto secretMbedtls = mbedtls.ecdhCompute(kpB->priv, kpA->pub);
    ASSERT_TRUE(secretOpenssl.has_value() && secretMbedtls.has_value());
    EXPECT_EQ(*secretOpenssl, *secretMbedtls);
}
