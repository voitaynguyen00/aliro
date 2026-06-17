#include <gtest/gtest.h>

#include "aliro/core/accessDocument.h"
#include "aliro/core/apdu.h"
#include "aliro/core/protocol.h"
#include "aliro/core/tlv.h"
#include "aliro/crypto/openSslCryptoProvider.h"
#include "aliro/device/deviceSession.h"

using namespace aliro;

class DeviceSessionTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;

    static AccessDocument makeTestAccessDoc() {
        AccessDocument doc;
        doc.docType = std::string(protocol::kAliroDocType);
        doc.issuerAuth.protectedHeader = Bytes{0xA0};
        doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
        doc.issuerAuth.payload = Bytes(8, 0x42);
        doc.issuerAuth.signature = Bytes(64, 0xAB);
        return doc;
    }

    Bytes buildAuth0Command(const EcPublicKey& readerEphPub, const Bytes& readerNonce,
                            const EcPublicKey& readerLongTermPub) {
        auto ephPubTlv = tlv::encode(protocol::kTagEphemeralPublicKey, readerEphPub.data);
        auto nonceTlv = tlv::encode(protocol::kTagReaderNonce, readerNonce);
        auto readerIdTlv = tlv::encode(protocol::kTagReaderIdentifier, readerLongTermPub.data);
        Bytes data;
        data.insert(data.end(), ephPubTlv->begin(), ephPubTlv->end());
        data.insert(data.end(), nonceTlv->begin(), nonceTlv->end());
        data.insert(data.end(), readerIdTlv->begin(), readerIdTlv->end());
        return apdu::buildCommand(protocol::kAliroCla, protocol::kInsAuth0, 0x00, 0x00, data);
    }

    Bytes buildAuth1Command(const Bytes& sig) {
        auto sigTlv = tlv::encode(protocol::kTagSignature, sig);
        return apdu::buildCommand(protocol::kAliroCla, protocol::kInsAuth1, 0x00, 0x00, *sigTlv);
    }
};

TEST_F(DeviceSessionTest, handleSelect_returnsSw9000) {
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    auto result = session.handleSelect(Bytes{0x00, 0xA4, 0x04, 0x00, 0x09});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, (Bytes{0x90, 0x00}));
}

TEST_F(DeviceSessionTest, handleAuth0_tooShortCommand_returnsDecodingError) {
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    Bytes shortCmd = {0x00, 0x87, 0x00, 0x00};  // missing Lc byte
    auto result = session.handleAuth0(shortCmd);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::DECODING_ERROR);
}

TEST_F(DeviceSessionTest, handleAuth0_missingEphemeralKey_returnsInvalidMessage) {
    auto deviceKp = mCrypto.generateKeyPair();
    auto readerKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value() && readerKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    auto nonce = mCrypto.randomBytes(16);
    ASSERT_TRUE(nonce.has_value());

    // Omit kTagEphemeralPublicKey — only nonce + reader identifier
    auto nonceTlv = tlv::encode(protocol::kTagReaderNonce, *nonce);
    auto readerIdTlv = tlv::encode(protocol::kTagReaderIdentifier, readerKp->pub.data);
    ASSERT_TRUE(nonceTlv.has_value() && readerIdTlv.has_value());
    Bytes data;
    data.insert(data.end(), nonceTlv->begin(), nonceTlv->end());
    data.insert(data.end(), readerIdTlv->begin(), readerIdTlv->end());
    auto cmd = apdu::buildCommand(protocol::kAliroCla, protocol::kInsAuth0, 0x00, 0x00, data);

    auto result = session.handleAuth0(cmd);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(DeviceSessionTest, handleAuth0_missingNonce_returnsInvalidMessage) {
    auto deviceKp = mCrypto.generateKeyPair();
    auto readerKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value() && readerKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    // Omit kTagReaderNonce — only ephemeral pub + reader identifier
    auto ephPubTlv = tlv::encode(protocol::kTagEphemeralPublicKey, readerKp->pub.data);
    auto readerIdTlv = tlv::encode(protocol::kTagReaderIdentifier, readerKp->pub.data);
    ASSERT_TRUE(ephPubTlv.has_value() && readerIdTlv.has_value());
    Bytes data;
    data.insert(data.end(), ephPubTlv->begin(), ephPubTlv->end());
    data.insert(data.end(), readerIdTlv->begin(), readerIdTlv->end());
    auto cmd = apdu::buildCommand(protocol::kAliroCla, protocol::kInsAuth0, 0x00, 0x00, data);

    auto result = session.handleAuth0(cmd);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(DeviceSessionTest, handleAuth0_missingReaderIdentifier_returnsInvalidMessage) {
    auto deviceKp = mCrypto.generateKeyPair();
    auto readerKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value() && readerKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    auto nonce = mCrypto.randomBytes(16);
    ASSERT_TRUE(nonce.has_value());

    // Omit kTagReaderIdentifier — only ephemeral pub + nonce
    auto ephPubTlv = tlv::encode(protocol::kTagEphemeralPublicKey, readerKp->pub.data);
    auto nonceTlv = tlv::encode(protocol::kTagReaderNonce, *nonce);
    ASSERT_TRUE(ephPubTlv.has_value() && nonceTlv.has_value());
    Bytes data;
    data.insert(data.end(), ephPubTlv->begin(), ephPubTlv->end());
    data.insert(data.end(), nonceTlv->begin(), nonceTlv->end());
    auto cmd = apdu::buildCommand(protocol::kAliroCla, protocol::kInsAuth0, 0x00, 0x00, data);

    auto result = session.handleAuth0(cmd);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(DeviceSessionTest, handleAuth0_validCommand_responseHasRequiredTlvFields) {
    auto deviceKp = mCrypto.generateKeyPair();
    auto readerKp = mCrypto.generateKeyPair();
    auto readerEphKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value() && readerKp.has_value() && readerEphKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    auto nonce = mCrypto.randomBytes(16);
    ASSERT_TRUE(nonce.has_value());

    auto cmd = buildAuth0Command(readerEphKp->pub, *nonce, readerKp->pub);
    auto result = session.handleAuth0(cmd);
    ASSERT_TRUE(result.has_value());

    // Response ends with SW 9000
    ASSERT_GE(result->size(), 2u);
    EXPECT_EQ((*result)[result->size() - 2], 0x90u);
    EXPECT_EQ((*result)[result->size() - 1], 0x00u);

    // Decode response body (strip SW) and verify all three required tags are present
    ByteView body(result->data(), result->size() - 2);
    auto items = tlv::decodeAll(body);
    ASSERT_TRUE(items.has_value());

    bool hasEphPub = false, hasNonce = false, hasSig = false;
    for (auto& item : *items) {
        if (item.tag == protocol::kTagEphemeralPublicKey &&
            item.value.size() == protocol::kEcPublicKeySize)
            hasEphPub = true;
        if (item.tag == protocol::kTagDeviceNonce && !item.value.empty())
            hasNonce = true;
        if (item.tag == protocol::kTagSignature && item.value.size() == protocol::kSignatureSize)
            hasSig = true;
    }
    EXPECT_TRUE(hasEphPub);
    EXPECT_TRUE(hasNonce);
    EXPECT_TRUE(hasSig);
}

TEST_F(DeviceSessionTest, handleAuth1_withoutPriorAuth0_returnsInvalidMessage) {
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    // mTranscript is empty — handleAuth1 must reject immediately
    auto cmd = buildAuth1Command(Bytes(64, 0x42));
    auto result = session.handleAuth1(cmd);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(DeviceSessionTest, handleAuth1_wrongSig_returnsInvalidMessage) {
    auto deviceKp = mCrypto.generateKeyPair();
    auto readerKp = mCrypto.generateKeyPair();
    auto readerEphKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value() && readerKp.has_value() && readerEphKp.has_value());
    DeviceSession session(mCrypto, deviceKp->priv, makeTestAccessDoc());

    auto nonce = mCrypto.randomBytes(16);
    ASSERT_TRUE(nonce.has_value());

    // Successful AUTH0 — sets mTranscript and mReaderLongTermPub
    auto auth0Cmd = buildAuth0Command(readerEphKp->pub, *nonce, readerKp->pub);
    auto auth0Result = session.handleAuth0(auth0Cmd);
    ASSERT_TRUE(auth0Result.has_value());

    // AUTH1 with a wrong (all-0x42) signature — verify() must return false
    auto auth1Cmd = buildAuth1Command(Bytes(64, 0x42));
    auto auth1Result = session.handleAuth1(auth1Cmd);
    ASSERT_FALSE(auth1Result.has_value());
    EXPECT_EQ(auth1Result.error(), AliroError::INVALID_MESSAGE);
}
