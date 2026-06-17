#include "aliro/device/deviceSession.h"
#include "aliro/reader/readerSession.h"
#include "aliro/core/protocol.h"
#include "aliro/crypto/openSslCryptoProvider.h"
#include "aliro/transport/simTransport.h"
#include <gtest/gtest.h>
#include <memory>

using namespace aliro;

class SessionFlowTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;

    // Build a minimal AccessDocument to vend from the device.
    static AccessDocument makeTestAccessDoc() {
        AccessDocument doc;
        doc.docType = std::string(protocol::kAliroDocType);
        doc.issuerAuth.protectedHeader   = Bytes{0xA0};
        doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
        doc.issuerAuth.payload           = Bytes(8, 0x42);
        doc.issuerAuth.signature         = Bytes(64, 0xAB);
        return doc;
    }
};

TEST_F(SessionFlowTest, fullAuth0Auth1ExchangeSucceeds) {
    // Generate long-term key pairs for both reader and device
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value());
    ASSERT_TRUE(deviceKp.has_value());

    AccessDocument accessDoc = makeTestAccessDoc();

    // Device session handles commands from the Reader
    auto deviceSession = std::make_shared<DeviceSession>(
        mCrypto, deviceKp->priv, accessDoc);

    // SimTransport routes Reader APDU commands through the DeviceSession
    SimTransport transport([&deviceSession](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() < 4) return tl::unexpected(AliroError::INVALID_MESSAGE);
        uint8_t ins = cmd[1];
        if (ins == protocol::kInsAuth0) return deviceSession->handleAuth0(cmd);
        if (ins == protocol::kInsAuth1) return deviceSession->handleAuth1(cmd);
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });

    // Reader runs the full authentication
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(readerKp->priv, deviceKp->pub);

    ASSERT_TRUE(result.has_value()) << "authenticate() failed";

    // Session keys must match on both sides
    EXPECT_EQ(result->sessionKey, deviceSession->sessionKey());
    EXPECT_EQ(result->sessionKey.size(), protocol::kAesKeySize);

    // AccessDocument must round-trip correctly
    EXPECT_EQ(result->accessDoc.docType, std::string(protocol::kAliroDocType));
    EXPECT_EQ(result->accessDoc.issuerAuth.signature, accessDoc.issuerAuth.signature);
}

TEST_F(SessionFlowTest, wrongDeviceKey_auth0VerificationFails) {
    auto readerKp  = mCrypto.generateKeyPair();
    auto deviceKp  = mCrypto.generateKeyPair();
    auto wrongKp   = mCrypto.generateKeyPair(); // Reader will try to verify with this
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value() && wrongKp.has_value());

    auto deviceSession = std::make_shared<DeviceSession>(
        mCrypto, deviceKp->priv, makeTestAccessDoc());

    SimTransport transport([&deviceSession](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() < 4) return tl::unexpected(AliroError::INVALID_MESSAGE);
        uint8_t ins = cmd[1];
        if (ins == protocol::kInsAuth0) return deviceSession->handleAuth0(cmd);
        if (ins == protocol::kInsAuth1) return deviceSession->handleAuth1(cmd);
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });

    // Reader verifies device signature against wrong key → should fail
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(readerKp->priv, wrongKp->pub);

    EXPECT_FALSE(result.has_value());
}

TEST_F(SessionFlowTest, sessionKeySymmetry_readerAndDeviceAgree) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto deviceSession = std::make_shared<DeviceSession>(
        mCrypto, deviceKp->priv, makeTestAccessDoc());

    SimTransport transport([&deviceSession](ByteView cmd) -> Result<Bytes> {
        uint8_t ins = cmd.size() >= 2 ? cmd[1] : 0;
        if (ins == protocol::kInsAuth0) return deviceSession->handleAuth0(cmd);
        if (ins == protocol::kInsAuth1) return deviceSession->handleAuth1(cmd);
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(readerKp->priv, deviceKp->pub);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->sessionKey, deviceSession->sessionKey());
    EXPECT_EQ(result->sessionKey.size(), 16u);
}

TEST_F(SessionFlowTest, transportError_duringAuth0_propagates) {
    auto readerKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value());

    // Transport always returns TRANSPORT_ERROR
    SimTransport transport([](ByteView) -> Result<Bytes> {
        return tl::unexpected(AliroError::TRANSPORT_ERROR);
    });

    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(deviceKp.has_value());

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(readerKp->priv, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::TRANSPORT_ERROR);
}

TEST_F(SessionFlowTest, malformedAuth0Response_returnsError) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    // AUTH0 returns garbage with valid SW
    SimTransport transport([](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() >= 2 && cmd[1] == protocol::kInsAuth0) {
            // Garbage TLV data + SW 0x9000
            return Bytes{0xFF, 0xFE, 0xFD, 0x90, 0x00};
        }
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(readerKp->priv, deviceKp->pub);

    EXPECT_FALSE(result.has_value());
}

TEST_F(SessionFlowTest, consecutiveSessions_independentKeys) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto run = [&]() -> Bytes {
        auto deviceSession = std::make_shared<DeviceSession>(
            mCrypto, deviceKp->priv, makeTestAccessDoc());
        SimTransport transport([&deviceSession](ByteView cmd) -> Result<Bytes> {
            uint8_t ins = cmd.size() >= 2 ? cmd[1] : 0;
            if (ins == protocol::kInsAuth0) return deviceSession->handleAuth0(cmd);
            if (ins == protocol::kInsAuth1) return deviceSession->handleAuth1(cmd);
            return tl::unexpected(AliroError::INVALID_MESSAGE);
        });
        ReaderSession reader(mCrypto, transport);
        auto r = reader.authenticate(readerKp->priv, deviceKp->pub);
        EXPECT_TRUE(r.has_value());
        return r.has_value() ? r->sessionKey : Bytes{};
    };

    auto key1 = run();
    auto key2 = run();
    EXPECT_NE(key1, key2); // Each session uses fresh ephemeral keys → different session key
    EXPECT_EQ(key1.size(), 16u);
    EXPECT_EQ(key2.size(), 16u);
}
