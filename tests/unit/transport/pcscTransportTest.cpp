#include <gtest/gtest.h>

#include "aliro/transport/pcscTransport.h"

using namespace aliro;

// ---------------------------------------------------------------------------
// Mock PC/SC functions — no real hardware required.
// ---------------------------------------------------------------------------

static LONG mockTransmit9000(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE, DWORD,
                              LPSCARD_IO_REQUEST, LPBYTE pbRecvBuffer, LPDWORD pcbRecvLength) {
    pbRecvBuffer[0] = 0x90;
    pbRecvBuffer[1] = 0x00;
    *pcbRecvLength  = 2;
    return SCARD_S_SUCCESS;
}

static LONG mockTransmitEcho(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE pbSendBuffer,
                              DWORD cbSendLength, LPSCARD_IO_REQUEST, LPBYTE pbRecvBuffer,
                              LPDWORD pcbRecvLength) {
    DWORD len       = std::min(cbSendLength, *pcbRecvLength);
    std::copy(pbSendBuffer, pbSendBuffer + len, pbRecvBuffer);
    *pcbRecvLength = len;
    return SCARD_S_SUCCESS;
}

static LONG mockTransmitFail(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE, DWORD,
                              LPSCARD_IO_REQUEST, LPBYTE, LPDWORD) {
    return SCARD_E_NO_SMARTCARD;
}

static LONG mockDisconnect(SCARDHANDLE, DWORD) {
    return SCARD_S_SUCCESS;
}

static int sDisconnectCallCount = 0;
static LONG countingDisconnect(SCARDHANDLE, DWORD) {
    ++sDisconnectCallCount;
    return SCARD_S_SUCCESS;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST(PcscTransportTest, isOpen_trueByDefault) {
    PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmit9000, mockDisconnect);
    EXPECT_TRUE(t.isOpen());
}

TEST(PcscTransportTest, close_setsIsOpenFalse) {
    PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmit9000, mockDisconnect);
    t.close();
    EXPECT_FALSE(t.isOpen());
}

TEST(PcscTransportTest, transceive_afterClose_returnsTransportError) {
    PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmit9000, mockDisconnect);
    t.close();
    auto resp = t.transceive({});
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), AliroError::TRANSPORT_ERROR);
}

TEST(PcscTransportTest, transceive_success_returns9000) {
    PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmit9000, mockDisconnect);
    auto resp = t.transceive(Bytes{0x00, 0xA4, 0x04, 0x00});
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(*resp, (Bytes{0x90, 0x00}));
}

TEST(PcscTransportTest, transceive_transmitError_returnsTransportError) {
    PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmitFail, mockDisconnect);
    auto resp = t.transceive(Bytes{0x01});
    ASSERT_FALSE(resp.has_value());
    EXPECT_EQ(resp.error(), AliroError::TRANSPORT_ERROR);
}

TEST(PcscTransportTest, transceive_echoesCommand_t0Protocol) {
    PcscTransport t(0, SCARD_PROTOCOL_T0, mockTransmitEcho, mockDisconnect);
    Bytes cmd = {0xDE, 0xAD, 0xBE, 0xEF};
    auto resp = t.transceive(cmd);
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(*resp, cmd);
}

TEST(PcscTransportTest, close_idempotent_callsDisconnectOnce) {
    sDisconnectCallCount = 0;
    PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmit9000, countingDisconnect);
    t.close();
    t.close();
    EXPECT_EQ(sDisconnectCallCount, 1);
}

TEST(PcscTransportTest, destructor_closesOpenTransport) {
    sDisconnectCallCount = 0;
    {
        PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmit9000, countingDisconnect);
        // t goes out of scope here → destructor must call close()
    }
    EXPECT_EQ(sDisconnectCallCount, 1);
}

TEST(PcscTransportTest, destructor_alreadyClosed_doesNotDisconnectAgain) {
    sDisconnectCallCount = 0;
    {
        PcscTransport t(0, SCARD_PROTOCOL_T1, mockTransmit9000, countingDisconnect);
        t.close();
        EXPECT_EQ(sDisconnectCallCount, 1);
        // destructor should not call disconnect a second time
    }
    EXPECT_EQ(sDisconnectCallCount, 1);
}
