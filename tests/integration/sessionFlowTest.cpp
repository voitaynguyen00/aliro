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

    static AccessDocument makeTestAccessDoc() {
        AccessDocument doc;
        doc.docType = std::string(protocol::kAliroDocType);
        doc.issuerAuth.protectedHeader   = Bytes{0xA0};
        doc.issuerAuth.unprotectedHeader = Bytes{0xA0};
        doc.issuerAuth.payload           = Bytes(8, 0x42);
        doc.issuerAuth.signature         = Bytes(64, 0xAB);
        return doc;
    }

    // Build a SimTransport that routes APDU INS bytes to the given DeviceSession.
    static SimTransport makeTransport(std::shared_ptr<DeviceSession> dev) {
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

TEST_F(SessionFlowTest, fullAuth0Auth1ExchangeSucceeds) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto dev = std::make_shared<DeviceSession>(mCrypto, deviceKp->priv, makeTestAccessDoc());
    auto transport = makeTransport(dev);

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_TRUE(result.has_value()) << "authenticate() failed";
    EXPECT_EQ(result->sessionKey, dev->sessionKey());
    EXPECT_EQ(result->sessionKey.size(), protocol::kAesKeySize);
    EXPECT_EQ(result->accessDoc.docType, std::string(protocol::kAliroDocType));
    EXPECT_EQ(result->accessDoc.issuerAuth.signature, makeTestAccessDoc().issuerAuth.signature);
}

TEST_F(SessionFlowTest, wrongDeviceKey_auth0VerificationFails) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    auto wrongKp  = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value() && wrongKp.has_value());

    auto dev = std::make_shared<DeviceSession>(mCrypto, deviceKp->priv, makeTestAccessDoc());
    auto transport = makeTransport(dev);

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, wrongKp->pub);  // wrong device key

    EXPECT_FALSE(result.has_value());
}

TEST_F(SessionFlowTest, wrongReaderKey_auth1VerificationFails) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    auto wrongKp  = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value() && wrongKp.has_value());

    // Build a mismatched key pair: advertise readerKp->pub in AUTH0 so the device
    // stores it, but sign the AUTH1 transcript with wrongKp->priv.
    // verify(transcript, sig_by_wrongKp_priv, readerKp->pub) must return false.
    EcKeyPair mismatchedKp{readerKp->pub, wrongKp->priv};

    auto dev = std::make_shared<DeviceSession>(mCrypto, deviceKp->priv, makeTestAccessDoc());
    auto transport = makeTransport(dev);
    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(mismatchedKp, deviceKp->pub);

    EXPECT_FALSE(result.has_value());
}

TEST_F(SessionFlowTest, sessionKeySymmetry_readerAndDeviceAgree) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto dev = std::make_shared<DeviceSession>(mCrypto, deviceKp->priv, makeTestAccessDoc());
    auto transport = makeTransport(dev);

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->sessionKey, dev->sessionKey());
    EXPECT_EQ(result->sessionKey.size(), 16u);
}

TEST_F(SessionFlowTest, transportError_duringAuth0_propagates) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    // Transport fails on everything after SELECT (returns TRANSPORT_ERROR on AUTH0)
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

TEST_F(SessionFlowTest, malformedAuth0Response_returnsError) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    SimTransport transport([](ByteView cmd) -> Result<Bytes> {
        if (cmd.size() >= 2 && cmd[1] == protocol::kInsSelect)
            return Bytes{0x90, 0x00};
        if (cmd.size() >= 2 && cmd[1] == protocol::kInsAuth0)
            return Bytes{0xFF, 0xFE, 0xFD, 0x90, 0x00};  // garbage TLV + SW 9000
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });

    ReaderSession reader(mCrypto, transport);
    auto result = reader.authenticate(*readerKp, deviceKp->pub);

    EXPECT_FALSE(result.has_value());
}

TEST_F(SessionFlowTest, consecutiveSessions_independentKeys) {
    auto readerKp = mCrypto.generateKeyPair();
    auto deviceKp = mCrypto.generateKeyPair();
    ASSERT_TRUE(readerKp.has_value() && deviceKp.has_value());

    auto run = [&]() -> Bytes {
        auto dev = std::make_shared<DeviceSession>(mCrypto, deviceKp->priv, makeTestAccessDoc());
        auto transport = makeTransport(dev);
        ReaderSession reader(mCrypto, transport);
        auto r = reader.authenticate(*readerKp, deviceKp->pub);
        EXPECT_TRUE(r.has_value());
        return r.has_value() ? r->sessionKey : Bytes{};
    };

    auto key1 = run();
    auto key2 = run();
    EXPECT_NE(key1, key2);
    EXPECT_EQ(key1.size(), 16u);
    EXPECT_EQ(key2.size(), 16u);
}
