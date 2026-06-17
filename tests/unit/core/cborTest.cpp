#include <gtest/gtest.h>

#include "aliro/core/cbor.h"

using namespace aliro;
using namespace aliro::cbor;

// --- Encoder tests (RFC 8949 Appendix A known-answer) ---

TEST(CborEncodeTest, uint_0) {
    Encoder enc;
    enc.addUint(0);
    EXPECT_EQ(enc.finish(), Bytes({0x00}));
}

TEST(CborEncodeTest, uint_23) {
    Encoder enc;
    enc.addUint(23);
    EXPECT_EQ(enc.finish(), Bytes({0x17}));
}

TEST(CborEncodeTest, uint_24) {
    Encoder enc;
    enc.addUint(24);
    EXPECT_EQ(enc.finish(), Bytes({0x18, 0x18}));
}

TEST(CborEncodeTest, uint_255) {
    Encoder enc;
    enc.addUint(255);
    EXPECT_EQ(enc.finish(), Bytes({0x18, 0xFF}));
}

TEST(CborEncodeTest, uint_256) {
    Encoder enc;
    enc.addUint(256);
    EXPECT_EQ(enc.finish(), Bytes({0x19, 0x01, 0x00}));
}

TEST(CborEncodeTest, negativeInt_minus1) {
    Encoder enc;
    enc.addInt(-1);
    EXPECT_EQ(enc.finish(), Bytes({0x20}));
}

TEST(CborEncodeTest, negativeInt_minus100) {
    Encoder enc;
    enc.addInt(-100);
    // -100 => major 1, value 99 = 0x63 => 0x38 0x63
    EXPECT_EQ(enc.finish(), Bytes({0x38, 0x63}));
}

TEST(CborEncodeTest, bytes_empty) {
    Encoder enc;
    enc.addBytes(Bytes{});
    EXPECT_EQ(enc.finish(), Bytes({0x40}));
}

TEST(CborEncodeTest, bytes_two) {
    Encoder enc;
    enc.addBytes(Bytes{0x01, 0x02});
    EXPECT_EQ(enc.finish(), Bytes({0x42, 0x01, 0x02}));
}

TEST(CborEncodeTest, text_empty) {
    Encoder enc;
    enc.addText("");
    EXPECT_EQ(enc.finish(), Bytes({0x60}));
}

TEST(CborEncodeTest, text_a) {
    Encoder enc;
    enc.addText("a");
    EXPECT_EQ(enc.finish(), Bytes({0x61, 0x61}));
}

TEST(CborEncodeTest, boolTrue) {
    Encoder enc;
    enc.addBool(true);
    EXPECT_EQ(enc.finish(), Bytes({0xF5}));
}

TEST(CborEncodeTest, boolFalse) {
    Encoder enc;
    enc.addBool(false);
    EXPECT_EQ(enc.finish(), Bytes({0xF4}));
}

TEST(CborEncodeTest, nullValue) {
    Encoder enc;
    enc.addNull();
    EXPECT_EQ(enc.finish(), Bytes({0xF6}));
}

TEST(CborEncodeTest, array_empty) {
    Encoder enc;
    enc.beginArray(0);
    EXPECT_EQ(enc.finish(), Bytes({0x80}));
}

TEST(CborEncodeTest, array_three_uints) {
    Encoder enc;
    enc.beginArray(3);
    enc.addUint(1);
    enc.addUint(2);
    enc.addUint(3);
    // [1,2,3] = 0x83 0x01 0x02 0x03
    EXPECT_EQ(enc.finish(), Bytes({0x83, 0x01, 0x02, 0x03}));
}

TEST(CborEncodeTest, map_one_entry) {
    Encoder enc;
    enc.beginMap(1);
    enc.addUint(1);
    enc.addText("a");
    // {1: "a"} = A1 01 61 61
    EXPECT_EQ(enc.finish(), Bytes({0xA1, 0x01, 0x61, 0x61}));
}

// --- Decoder tests ---

TEST(CborDecodeTest, uint) {
    Bytes data = {0x18, 0x64};  // 100
    Decoder dec(data);
    auto v = dec.getUint();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, 100u);
    EXPECT_TRUE(dec.isAtEnd());
}

TEST(CborDecodeTest, negInt) {
    Bytes data = {0x20};  // -1
    Decoder dec(data);
    auto v = dec.getInt();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, -1);
}

TEST(CborDecodeTest, bytes) {
    Bytes data = {0x42, 0xDE, 0xAD};
    Decoder dec(data);
    auto v = dec.getBytes();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, (Bytes{0xDE, 0xAD}));
}

TEST(CborDecodeTest, text) {
    Bytes data = {0x65, 0x61, 0x6C, 0x69, 0x72, 0x6F};  // "aliro"
    Decoder dec(data);
    auto v = dec.getText();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "aliro");
}

TEST(CborDecodeTest, boolTrue) {
    Bytes data = {0xF5};
    Decoder dec(data);
    auto v = dec.getBool();
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, true);
}

TEST(CborDecodeTest, mapSize) {
    Bytes data = {0xA2, 0x01, 0x02, 0x03, 0x04};  // {1:2, 3:4}
    Decoder dec(data);
    auto count = dec.getMapSize();
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(*count, 2u);
}

TEST(CborDecodeTest, wrongType_returnsError) {
    Bytes data = {0x61, 0x61};  // text "a"
    Decoder dec(data);
    auto v = dec.getUint();  // wrong type
    EXPECT_FALSE(v.has_value());
    EXPECT_EQ(v.error(), AliroError::DECODING_ERROR);
}

TEST(CborRoundTripTest, mapWithMixedValues) {
    Encoder enc;
    enc.beginMap(3);
    enc.addUint(1);
    enc.addUint(42);
    enc.addUint(2);
    enc.addText("aliro");
    enc.addUint(3);
    enc.addBytes(Bytes{0xAA, 0xBB});
    Bytes encoded = enc.finish();

    Decoder dec(encoded);
    auto count = dec.getMapSize();
    ASSERT_TRUE(count.has_value());
    EXPECT_EQ(*count, 3u);

    EXPECT_EQ(*dec.getUint(), 1u);
    EXPECT_EQ(*dec.getUint(), 42u);
    EXPECT_EQ(*dec.getUint(), 2u);
    EXPECT_EQ(*dec.getText(), "aliro");
    EXPECT_EQ(*dec.getUint(), 3u);
    EXPECT_EQ(*dec.getBytes(), (Bytes{0xAA, 0xBB}));
    EXPECT_TRUE(dec.isAtEnd());
}
