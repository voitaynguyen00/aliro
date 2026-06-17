#include "aliro/core/revocationDocument.h"
#include "aliro/core/protocol.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(RevocationDocumentTest, encodeDecodeRoundTrip_overwrite) {
    RevocationDocument doc;
    doc.docType = std::string(protocol::kRevocationDocType);
    doc.issuerAuth.protectedHeader   = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload           = Bytes(8, 0x00);
    doc.issuerAuth.signature         = Bytes(64, 0xDD);

    RevocationDataElement elem;
    elem.version    = 1;
    elem.changeMode = ChangeMode::OVERWRITE;
    elem.entries.push_back({Bytes{0x01, 0x02, 0x03, 0x04}});
    doc.revocationElements.push_back(elem);

    auto encoded = encodeRevocationDocument(doc);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeRevocationDocument(*encoded);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->revocationElements.size(), 1u);
    EXPECT_EQ(decoded->revocationElements[0].changeMode, ChangeMode::OVERWRITE);
    ASSERT_EQ(decoded->revocationElements[0].entries.size(), 1u);
    EXPECT_EQ(decoded->revocationElements[0].entries[0].credentialId,
              (Bytes{0x01, 0x02, 0x03, 0x04}));
}

TEST(RevocationDocumentTest, encodeDecodeRoundTrip_update_withRemove) {
    RevocationDocument doc;
    doc.docType = std::string(protocol::kRevocationDocType);
    doc.issuerAuth.protectedHeader   = Bytes{0xA0};
    doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
    doc.issuerAuth.payload           = Bytes(8, 0x00);
    doc.issuerAuth.signature         = Bytes(64, 0xEE);

    RevocationDataElement elem;
    elem.version    = 1;
    elem.changeMode = ChangeMode::UPDATE;
    elem.entries.push_back({Bytes{0xAA, 0xBB}});
    elem.entriesRemove.push_back({Bytes{0xCC, 0xDD}});
    doc.revocationElements.push_back(elem);

    auto encoded = encodeRevocationDocument(doc);
    ASSERT_TRUE(encoded.has_value());

    auto decoded = decodeRevocationDocument(*encoded);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->revocationElements[0].changeMode, ChangeMode::UPDATE);
    EXPECT_EQ(decoded->revocationElements[0].entries[0].credentialId, (Bytes{0xAA, 0xBB}));
    EXPECT_EQ(decoded->revocationElements[0].entriesRemove[0].credentialId, (Bytes{0xCC, 0xDD}));
}

TEST(RevocationDocumentTest, decodeMalformed_returnsError) {
    Bytes garbage = {0xDE, 0xAD};
    EXPECT_FALSE(decodeRevocationDocument(garbage).has_value());
}
