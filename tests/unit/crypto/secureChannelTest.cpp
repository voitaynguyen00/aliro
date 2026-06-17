#include "aliro/crypto/secureChannel.h"
#include "aliro/crypto/openSslCryptoProvider.h"
#include <gtest/gtest.h>

using namespace aliro;

class SecureChannelTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;
    const Bytes mKey{Bytes(16, 0x42)};
};

TEST_F(SecureChannelTest, encryptDecryptRoundTrip) {
    SecureChannel sender(mCrypto, mKey);
    SecureChannel receiver(mCrypto, mKey);

    Bytes plaintext = {0x01, 0x02, 0x03, 0x04};
    auto ct = sender.encrypt(plaintext);
    ASSERT_TRUE(ct.has_value());

    auto pt = receiver.decrypt(*ct);
    ASSERT_TRUE(pt.has_value());
    EXPECT_EQ(*pt, plaintext);
}

TEST_F(SecureChannelTest, emptyPlaintext_roundTrip) {
    SecureChannel sender(mCrypto, mKey);
    SecureChannel receiver(mCrypto, mKey);

    auto ct = sender.encrypt({});
    ASSERT_TRUE(ct.has_value());
    EXPECT_EQ(ct->size(), 16u);  // only the 16-byte GCM tag

    auto pt = receiver.decrypt(*ct);
    ASSERT_TRUE(pt.has_value());
    EXPECT_TRUE(pt->empty());
}

TEST_F(SecureChannelTest, consecutiveEncryptsUseDifferentNonces) {
    SecureChannel channel(mCrypto, mKey);

    Bytes plaintext(32, 0xAB);
    auto ct1 = channel.encrypt(plaintext);
    auto ct2 = channel.encrypt(plaintext);
    ASSERT_TRUE(ct1.has_value() && ct2.has_value());
    // Counter increments each call so the same plaintext produces different ciphertext
    EXPECT_NE(*ct1, *ct2);
}

TEST_F(SecureChannelTest, aad_encryptDecryptRoundTrip) {
    SecureChannel sender(mCrypto, mKey);
    SecureChannel receiver(mCrypto, mKey);

    Bytes plaintext = {0xDE, 0xAD, 0xBE, 0xEF};
    Bytes aad       = {0x00, 0x01, 0x02};

    auto ct = sender.encrypt(plaintext, aad);
    ASSERT_TRUE(ct.has_value());

    auto pt = receiver.decrypt(*ct, aad);
    ASSERT_TRUE(pt.has_value());
    EXPECT_EQ(*pt, plaintext);
}

TEST_F(SecureChannelTest, decrypt_corruptedCiphertext_returnsError) {
    SecureChannel sender(mCrypto, mKey);
    SecureChannel receiver(mCrypto, mKey);

    auto ct = sender.encrypt(Bytes{0x01, 0x02, 0x03});
    ASSERT_TRUE(ct.has_value());

    ct->back() ^= 0xFF;  // corrupt the GCM tag
    auto pt = receiver.decrypt(*ct);
    EXPECT_FALSE(pt.has_value());
}

TEST_F(SecureChannelTest, aad_mismatch_returnsError) {
    SecureChannel sender(mCrypto, mKey);
    SecureChannel receiver(mCrypto, mKey);

    auto ct = sender.encrypt(Bytes{0x01, 0x02}, Bytes{0xAA});
    ASSERT_TRUE(ct.has_value());

    auto pt = receiver.decrypt(*ct, Bytes{0xBB});  // wrong AAD
    EXPECT_FALSE(pt.has_value());
}

TEST_F(SecureChannelTest, sendAndReceiveCountersAreIndependent) {
    SecureChannel a(mCrypto, mKey);
    SecureChannel b(mCrypto, mKey);

    // a → b: two messages
    auto ct1 = a.encrypt(Bytes{0x01});
    auto ct2 = a.encrypt(Bytes{0x02});
    ASSERT_TRUE(ct1.has_value() && ct2.has_value());

    auto pt1 = b.decrypt(*ct1);
    auto pt2 = b.decrypt(*ct2);
    ASSERT_TRUE(pt1.has_value() && pt2.has_value());
    EXPECT_EQ(*pt1, (Bytes{0x01}));
    EXPECT_EQ(*pt2, (Bytes{0x02}));

    // b → a: independent counter starting at 0
    auto ct3 = b.encrypt(Bytes{0x03});
    ASSERT_TRUE(ct3.has_value());
    auto pt3 = a.decrypt(*ct3);
    ASSERT_TRUE(pt3.has_value());
    EXPECT_EQ(*pt3, (Bytes{0x03}));
}
