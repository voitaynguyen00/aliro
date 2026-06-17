#include "aliro/core/issuerAuth.h"
#include "aliro/core/cbor.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(IssuerSignedItemTest, encodeDecodeRoundTrip) {
    IssuerSignedItem item;
    item.digestId = 1;
    item.random   = Bytes(16, 0xAA);
    item.elementIdentifier = "some.element";
    item.elementValue      = Bytes{0x41, 0x01}; // CBOR-encoded uint 1

    auto encoded = encodeIssuerSignedItem(item);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeIssuerSignedItem(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->digestId, item.digestId);
    EXPECT_EQ(decoded->random, item.random);
    EXPECT_EQ(decoded->elementIdentifier, item.elementIdentifier);
    EXPECT_EQ(decoded->elementValue, item.elementValue);
}

TEST(IssuerAuthTest, encodeDecodeRoundTrip) {
    IssuerAuth auth;
    auth.protectedHeader   = Bytes{0xA1, 0x01, 0x26}; // CBOR {"alg": -7}
    auth.unprotectedHeader = Bytes{0xA0};              // CBOR {}
    auth.payload           = Bytes(32, 0xBB);
    auth.signature         = Bytes(64, 0xCC);

    auto encoded = encodeIssuerAuth(auth);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeIssuerAuth(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->protectedHeader,   auth.protectedHeader);
    EXPECT_EQ(decoded->unprotectedHeader, auth.unprotectedHeader);
    EXPECT_EQ(decoded->payload,           auth.payload);
    EXPECT_EQ(decoded->signature,         auth.signature);
}

TEST(IssuerAuthTest, decodeMalformedData_returnsError) {
    Bytes garbage = {0x01, 0x02, 0x03};
    auto result = decodeIssuerAuth(garbage);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::DECODING_ERROR);
}

TEST(IssuerAuthTest, signatureWrongSize_returnsError) {
    cbor::Encoder enc;
    enc.beginArray(4);
    enc.addBytes(Bytes{0xA1, 0x01, 0x26}); // protected
    enc.addBytes(Bytes{0xA0});              // unprotected
    enc.addBytes(Bytes(32, 0xBB));          // payload
    enc.addBytes(Bytes(32, 0xCC));          // signature — wrong: must be 64 bytes
    Bytes data = enc.finish();

    auto result = decodeIssuerAuth(data);
    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}
