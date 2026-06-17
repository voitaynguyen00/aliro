#include <gtest/gtest.h>

#include "aliro/core/accessDocument.h"
#include "aliro/core/protocol.h"

using namespace aliro;

TEST(AccessDocumentTest, encodeDecodeRoundTrip_minimal) {
    AccessDocument doc;
    doc.docType = std::string(protocol::kAliroDocType);
    doc.issuerAuth.protectedHeader = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload = Bytes(16, 0x00);
    doc.issuerAuth.signature = Bytes(64, 0xAB);

    auto encoded = encodeAccessDocument(doc);
    ASSERT_TRUE(encoded.has_value()) << "encode failed";

    auto decoded = decodeAccessDocument(*encoded);
    ASSERT_TRUE(decoded.has_value()) << "decode failed";

    EXPECT_EQ(decoded->docType, doc.docType);
    EXPECT_EQ(decoded->issuerAuth.signature, doc.issuerAuth.signature);
    EXPECT_EQ(decoded->issuerAuth.payload, doc.issuerAuth.payload);
}

TEST(AccessDocumentTest, encodeDecodeRoundTrip_withNamespace) {
    AccessDocument doc;
    doc.docType = std::string(protocol::kAliroDocType);
    doc.issuerAuth.protectedHeader = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload = Bytes(16, 0x11);
    doc.issuerAuth.signature = Bytes(64, 0xFF);

    NameSpaceItems ns;
    ns.nameSpace = std::string(protocol::kAliroNameSpace);
    ns.issuerSignedItems.push_back(Bytes{0x42, 0xAA, 0xBB});  // dummy item bytes
    doc.nameSpaces.push_back(std::move(ns));

    auto encoded = encodeAccessDocument(doc);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeAccessDocument(*encoded);
    ASSERT_TRUE(decoded.has_value());

    ASSERT_EQ(decoded->nameSpaces.size(), 1u);
    EXPECT_EQ(decoded->nameSpaces[0].nameSpace, std::string(protocol::kAliroNameSpace));
    ASSERT_EQ(decoded->nameSpaces[0].issuerSignedItems.size(), 1u);
}

TEST(AccessDocumentTest, decodeMalformed_returnsError) {
    Bytes garbage = {0xFF, 0xFE, 0xFD};
    auto result = decodeAccessDocument(garbage);
    EXPECT_FALSE(result.has_value());
}
