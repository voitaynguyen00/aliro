#include "aliro/transport/simTransport.h"
#include <gtest/gtest.h>

using namespace aliro;

TEST(SimTransportTest, transceive_callsHandler_echoResponse) {
    SimTransport t([](ByteView cmd) -> Result<Bytes> {
        return Bytes(cmd.begin(), cmd.end());
    });
    Bytes cmd = {0x01, 0x02, 0x03};
    auto resp = t.transceive(cmd);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(*resp, cmd);
}

TEST(SimTransportTest, isOpen_trueByDefault) {
    SimTransport t([](ByteView) -> Result<Bytes> { return Bytes{}; });
    EXPECT_TRUE(t.isOpen());
}

TEST(SimTransportTest, close_setsIsOpenFalse) {
    SimTransport t([](ByteView) -> Result<Bytes> { return Bytes{}; });
    t.close();
    EXPECT_FALSE(t.isOpen());
}

TEST(SimTransportTest, transceive_afterClose_returnsTransportError) {
    SimTransport t([](ByteView) -> Result<Bytes> { return Bytes{}; });
    t.close();
    auto resp = t.transceive({});
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), AliroError::TRANSPORT_ERROR);
}

TEST(SimTransportTest, handler_errorPropagatesThrough) {
    SimTransport t([](ByteView) -> Result<Bytes> {
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    });
    auto resp = t.transceive(Bytes{0x01});
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), AliroError::INVALID_MESSAGE);
}

TEST(SimTransportTest, multipleTransceive_handlerCalledEachTime) {
    int callCount = 0;
    SimTransport t([&callCount](ByteView) -> Result<Bytes> {
        ++callCount;
        return Bytes{static_cast<uint8_t>(callCount)};
    });
    EXPECT_EQ(t.transceive({})->at(0), 1u);
    EXPECT_EQ(t.transceive({})->at(0), 2u);
    EXPECT_EQ(callCount, 2);
}
