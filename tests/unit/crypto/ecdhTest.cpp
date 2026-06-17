#include "aliro/crypto/openSslCryptoProvider.h"
#include <gtest/gtest.h>

using namespace aliro;

class EcdhTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;
};

TEST_F(EcdhTest, dhSymmetry) {
    auto kpA = mCrypto.generateKeyPair();
    auto kpB = mCrypto.generateKeyPair();
    ASSERT_TRUE(kpA.has_value());
    ASSERT_TRUE(kpB.has_value());

    auto secretAB = mCrypto.ecdhCompute(kpA->priv, kpB->pub);
    auto secretBA = mCrypto.ecdhCompute(kpB->priv, kpA->pub);

    ASSERT_TRUE(secretAB.has_value());
    ASSERT_TRUE(secretBA.has_value());
    EXPECT_EQ(*secretAB, *secretBA);
    EXPECT_EQ(secretAB->size(), 32u);
}

TEST_F(EcdhTest, differentPairsProduceDifferentSecrets) {
    auto kpA = mCrypto.generateKeyPair();
    auto kpB = mCrypto.generateKeyPair();
    auto kpC = mCrypto.generateKeyPair();
    ASSERT_TRUE(kpA.has_value() && kpB.has_value() && kpC.has_value());

    auto secretAB = mCrypto.ecdhCompute(kpA->priv, kpB->pub);
    auto secretAC = mCrypto.ecdhCompute(kpA->priv, kpC->pub);

    ASSERT_TRUE(secretAB.has_value() && secretAC.has_value());
    EXPECT_NE(*secretAB, *secretAC);
}
