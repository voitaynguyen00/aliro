#include <gtest/gtest.h>

#include "aliro/crypto/openSslCryptoProvider.h"

using namespace aliro;

class RandomTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;
};

TEST_F(RandomTest, returnsRequestedLength) {
    auto r = mCrypto.randomBytes(32);
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->size(), 32u);
}

TEST_F(RandomTest, twoCallsProduceDifferentBytes) {
    auto r1 = mCrypto.randomBytes(16);
    auto r2 = mCrypto.randomBytes(16);
    ASSERT_TRUE(r1.has_value() && r2.has_value());
    EXPECT_NE(*r1, *r2);
}

TEST_F(RandomTest, zeroLength_returnsEmpty) {
    auto r = mCrypto.randomBytes(0);
    ASSERT_TRUE(r.has_value());
    EXPECT_TRUE(r->empty());
}
