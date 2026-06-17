#include "aliro/reader/readerSession.h"
#include "aliro/device/deviceSession.h"
#include "aliro/core/accessDocument.h"
#include "aliro/core/protocol.h"
#include "aliro/core/tlv.h"
#include "aliro/crypto/openSslCryptoProvider.h"
#include "aliro/transport/simTransport.h"
#include <gtest/gtest.h>
#include <memory>

using namespace aliro;

class ReaderSessionTest : public ::testing::Test {
protected:
    OpenSslCryptoProvider mCrypto;

    static AccessDocument makeTestAccessDoc() {
        AccessDocument doc;
        doc.docType = std::string(protocol::kAliroDocType);
        doc.issuerAuth.protectedHeader   = Bytes{0xA0};
        doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
        doc.issuerAuth.payload           = Bytes(8, 0x42);
        doc.issuerAuth.signature         = Bytes(64, 0xAB);
        return doc;
    }

    // Build a fake AUTH0 response body with the given TLV tags appended to SW 9000.
    static Bytes fakeAuth0Response(const std::vector<std::pair<uint32_t, Bytes>>& fields) {
        Bytes resp;
        for (auto& [tag, value] : fields) {
            auto tlvBytes = tlv::encode(tag, value);
            if (tlvBytes) resp.insert(resp.end(), tlvBytes->begin(), tlvBytes->end());
        }
        resp.push_back(0x90);
        resp.push_back(0x00);
        return resp;
    }

    // A SimTransport that answers SELECT with SW 9000 and AUTH0 with a custom response.
    static SimTransport transportWithFakeAuth0(Bytes auth0Response) {
        return SimTransport([r = std::move(auth0Response)](ByteView cmd) mutable -> Result<Bytes> {
            if (cmd.size() < 2) return tl::unexpected(AliroError::INVALID_MESSAGE);
            uint8_t ins = cmd[1];
            if (ins == protocol::kInsSelect) return Bytes{0x90, 0x00};
            if (ins == protocol::kInsAuth0)  return r;
            return tl::unexpected(AliroError::INVALID_MESSAGE);
        });
    }

    // A full device-backed transport for tests that need AUTH0 to actually succeed.
    SimTransport makeDeviceTransport(std::shared_ptr<DeviceSession> dev) {
        return SimTransport([dev](ByteView cmd) -> Result<Bytes> {
            if (cmd.size() < 2) return tl::unexpected(AliroError::INVALID_MESSAGE);
            uint8_t ins = cmd[1];
            if (ins == protocol::kInsSelect) return dev->handleSelect(cmd);
            if (ins == protocol::kInsAuth0)  return dev->handleAuth0(cmd);
            if (ins == protocol::kInsAuth1)  return dev->handleAuth1(cmd);
            return tl::unexpected(AliroError::INVALID_MESSAGE);
        });
    }
};

// ---- SELECT error paths ---------------------------------------------------

TEST_F(ReaderSessionTest, select_nonSuccessSw_returnsInvalidMessage) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    SimTransport transport([](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() >= 2 && cmd[1] == protocol::kInsSelect)
            return Bytes{0x6A, 0x82};  // File not found
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(ReaderSessionTest, select_transportError_propagates) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    SimTransport transport([](ByteView) -> Result<Bytes> {
        return tl::unexpected(AliroError::TRANSPORT_ERROR);
    });
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::TRANSPORT_ERROR);
}

// ---- AUTH0 error paths ----------------------------------------------------

TEST_F(ReaderSessionTest, auth0_transportError_propagates) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    SimTransport transport([](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() >= 2 && cmd[1] == protocol::kInsSelect)
            return Bytes{0x90, 0x00};
        return tl::unexpected(AliroError::TRANSPORT_ERROR);
    });
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::TRANSPORT_ERROR);
}

TEST_F(ReaderSessionTest, auth0_missingEphemeralKey_returnsInvalidMessage) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    // Response omits kTagEphemeralPublicKey
    auto resp = fakeAuth0Response({
        {protocol::kTagDeviceNonce, Bytes(16, 0xBB)},
        {protocol::kTagSignature,   Bytes(64, 0xCC)},
    });
    auto transport = transportWithFakeAuth0(std::move(resp));
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(ReaderSessionTest, auth0_missingDeviceNonce_returnsInvalidMessage) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto resp = fakeAuth0Response({
        {protocol::kTagEphemeralPublicKey, Bytes(65, 0xAA)},
        {protocol::kTagSignature,          Bytes(64, 0xCC)},
    });
    auto transport = transportWithFakeAuth0(std::move(resp));
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(ReaderSessionTest, auth0_missingSignature_returnsInvalidMessage) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto resp = fakeAuth0Response({
        {protocol::kTagEphemeralPublicKey, Bytes(65, 0xAA)},
        {protocol::kTagDeviceNonce,        Bytes(16, 0xBB)},
    });
    auto transport = transportWithFakeAuth0(std::move(resp));
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

TEST_F(ReaderSessionTest, auth0_wrongSizedSignature_returnsInvalidMessage) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto resp = fakeAuth0Response({
        {protocol::kTagEphemeralPublicKey, Bytes(65, 0xAA)},
        {protocol::kTagDeviceNonce,        Bytes(16, 0xBB)},
        {protocol::kTagSignature,          Bytes(32, 0xCC)},  // 32, not 64
    });
    auto transport = transportWithFakeAuth0(std::move(resp));
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::INVALID_MESSAGE);
}

// ---- AUTH1 error paths ----------------------------------------------------

TEST_F(ReaderSessionTest, auth1_transportError_propagates) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    // Device handles SELECT and AUTH0 correctly; AUTH1 transport fails.
    auto dev = std::make_shared<DeviceSession>(mCrypto, deviceKp->priv, makeTestAccessDoc());
    SimTransport transport([dev](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() < 2) return tl::unexpected(AliroError::INVALID_MESSAGE);
        uint8_t ins = cmd[1];
        if (ins == protocol::kInsSelect) return dev->handleSelect(cmd);
        if (ins == protocol::kInsAuth0)  return dev->handleAuth0(cmd);
        return tl::unexpected(AliroError::TRANSPORT_ERROR);  // AUTH1 fails
    });

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), AliroError::TRANSPORT_ERROR);
}
