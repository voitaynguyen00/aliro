#include "aliro/core/tlv.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(TlvEncodeTest, singleByteTag_shortValue) {
    Bytes value = {0x01, 0x02, 0x03};
    auto result = tlv::encode(0x41, value);
    ASSERT_TRUE(result.has_value());
    Bytes expected = {0x41, 0x03, 0x01, 0x02, 0x03};
    EXPECT_EQ(*result, expected);
}

TEST(TlvEncodeTest, twoByteTag_emptyValue) {
    Bytes value = {};
    auto result = tlv::encode(0x7F21, value);
    ASSERT_TRUE(result.has_value());
    Bytes expected = {0x7F, 0x21, 0x00};
    EXPECT_EQ(*result, expected);
}

TEST(TlvEncodeTest, lengthRequires2Bytes) {
    Bytes value(128, 0xAB);
    auto result = tlv::encode(0x50, value);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)[0], 0x50);
    EXPECT_EQ((*result)[1], 0x81);
    EXPECT_EQ((*result)[2], 128);
    EXPECT_EQ(result->size(), 3u + 128u);
}

TEST(TlvEncodeTest, lengthRequires3Bytes) {
    Bytes value(300, 0xCD);
    auto result = tlv::encode(0x50, value);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ((*result)[1], 0x82);
    EXPECT_EQ((*result)[2], 0x01);
    EXPECT_EQ((*result)[3], 0x2C); // 300 = 0x012C
    EXPECT_EQ(result->size(), 4u + 300u);
}

TEST(TlvDecodeTest, decodeOneItem) {
    Bytes data = {0x41, 0x03, 0x01, 0x02, 0x03};
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tag, 0x41u);
    EXPECT_EQ(result->value, (Bytes{0x01, 0x02, 0x03}));
    EXPECT_EQ(consumed, 5u);
}

TEST(TlvDecodeTest, decodeTwoByteTag) {
    Bytes data = {0x7F, 0x21, 0x02, 0xAA, 0xBB};
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->tag, 0x7F21u);
    EXPECT_EQ(result->value, (Bytes{0xAA, 0xBB}));
    EXPECT_EQ(consumed, 5u);
}

TEST(TlvDecodeTest, emptyData_returnsError) {
    Bytes data = {};
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::DECODING_ERROR);
}

TEST(TlvDecodeTest, truncatedValue_returnsError) {
    Bytes data = {0x41, 0x05, 0x01, 0x02}; // length=5 but only 2 value bytes
    size_t consumed = 0;
    auto result = tlv::decodeOne(data, consumed);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::DECODING_ERROR);
}

TEST(TlvRoundTripTest, encodeDecodeRoundTrip) {
    Bytes value = {0xDE, 0xAD, 0xBE, 0xEF};
    auto encoded = tlv::encode(0x5A, value);
    ASSERT_TRUE(encoded.has_value());
    size_t consumed = 0;
    auto decoded = tlv::decodeOne(*encoded, consumed);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->tag, 0x5Au);
    EXPECT_EQ(decoded->value, value);
    EXPECT_EQ(consumed, encoded->size());
}

// Regression: tags 0x80–0xFF with (& 0x1F != 0x1F) must be single-byte.
TEST(TlvRoundTripTest, aliroProtocolTags_roundTrip) {
    const uint32_t tags[] = {
        0x86, // kTagEphemeralPublicKey
        0x85, // kTagReaderNonce
        0x8A, // kTagDeviceNonce
        0x9E, // kTagSignature
        0x9D, // kTagCryptogram
        0x83, // kTagReaderIdentifier
        0xA7, // kTagDeviceRequest
        0xA8, // kTagDeviceResponse
    };
    for (uint32_t tag : tags) {
        Bytes value = {0xDE, 0xAD};
        auto encoded = tlv::encode(tag, value);
        ASSERT_TRUE(encoded.has_value()) << "encode failed for tag 0x" << std::hex << tag;
        EXPECT_EQ(encoded->at(0), static_cast<uint8_t>(tag))
            << "tag 0x" << std::hex << tag << " must encode as single byte";

        size_t consumed = 0;
        auto decoded = tlv::decodeOne(*encoded, consumed);
        ASSERT_TRUE(decoded.has_value()) << "decode failed for tag 0x" << std::hex << tag;
        EXPECT_EQ(decoded->tag, tag) << "tag mismatch for 0x" << std::hex << tag;
        EXPECT_EQ(decoded->value, value);
    }
}

TEST(TlvDecodeAllTest, multipleConcatenatedItems) {
    auto item1 = tlv::encode(0x01, Bytes{0xAA});
    auto item2 = tlv::encode(0x02, Bytes{0xBB, 0xCC});
    ASSERT_TRUE(item1.has_value());
    ASSERT_TRUE(item2.has_value());
    Bytes combined;
    combined.insert(combined.end(), item1->begin(), item1->end());
    combined.insert(combined.end(), item2->begin(), item2->end());

    auto result = tlv::decodeAll(combined);
    ASSERT_TRUE(result.has_value());
    ASSERT_EQ(result->size(), 2u);
    EXPECT_EQ((*result)[0].tag, 0x01u);
    EXPECT_EQ((*result)[0].value, (Bytes{0xAA}));
    EXPECT_EQ((*result)[1].tag, 0x02u);
    EXPECT_EQ((*result)[1].value, (Bytes{0xBB, 0xCC}));
}
