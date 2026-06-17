#include "aliro/crypto/openSslCryptoProvider.h"
#include "aliro/core/protocol.h"
#include <gtest/gtest.h>

using namespace aliro;

class CryptoTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;
};

TEST_F(CryptoTest, generateKeyPair_pubKeyIs65Bytes) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->pub.data.size(), protocol::kEcPublicKeySize);
    EXPECT_EQ(kp->pub.data[0], 0x04);
}

TEST_F(CryptoTest, generateKeyPair_privKeyIs32Bytes) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    EXPECT_EQ(kp->priv.data.size(), protocol::kEcPrivateKeySize);
}

TEST_F(CryptoTest, generateKeyPair_twoCallsProduceDifferentKeys) {
    auto kp1 = mCrypto.generateKeyPair();
    auto kp2 = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp1.has_value());
    ASSERT_TRUE(kp2.has_value());
    EXPECT_NE(kp1->pub.data, kp2->pub.data);
}

TEST_F(CryptoTest, sign_producesValidSignature) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    Bytes msg = {0x01, 0x02, 0x03, 0x04};
    auto sig = mCrypto.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());
    EXPECT_EQ(sig->data.size(), 64u);
}

TEST_F(CryptoTest, verify_validSignatureReturnsTrue) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    Bytes msg = {0xDE, 0xAD, 0xBE, 0xEF};
    auto sig = mCrypto.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());
    auto ok = mCrypto.verify(msg, *sig, kp->pub);
    ASSERT_TRUE(ok.has_value());
    EXPECT_TRUE(*ok);
}

TEST_F(CryptoTest, verify_wrongMessageReturnsFalse) {
    auto kp = mCrypto.generateKeyPair();
    ASSERT_TRUE(kp.has_value());
    Bytes msg   = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes other = {0xCA, 0xFE, 0xBA, 0xBE};
    auto sig = mCrypto.sign(msg, kp->priv);
    ASSERT_TRUE(sig.has_value());
    auto ok = mCrypto.verify(other, *sig, kp->pub);
    ASSERT_TRUE(ok.has_value());
    EXPECT_FALSE(*ok);
}

TEST_F(CryptoTest, verify_wrongKeyReturnsFalse) {
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
