#include "aliro/transport/pcscTransport.h"

namespace aliro {

namespace {
constexpr DWORD kMaxApduResponse = 258;  // 256-byte Ne + 2-byte SW (ISO 7816-4 short APDU)
}

PcscTransport::PcscTransport(SCARDHANDLE handle, DWORD protocol, TransmitFn transmitFn,
                              DisconnectFn disconnectFn)
    : mHandle(handle), mProtocol(protocol), mTransmitFn(transmitFn), mDisconnectFn(disconnectFn) {}

PcscTransport::~PcscTransport() {
    if (mIsOpen)
        close();
}

Result<Bytes> PcscTransport::transceive(ByteView command) {
    if (!mIsOpen)
        return tl::unexpected(AliroError::TRANSPORT_ERROR);

    const SCARD_IO_REQUEST* pioSend =
        (mProtocol == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;

    Bytes response(kMaxApduResponse);
    DWORD responseLen = static_cast<DWORD>(response.size());

    LONG rv = mTransmitFn(mHandle, pioSend, command.data(),
                          static_cast<DWORD>(command.size()), nullptr, response.data(),
                          &responseLen);

    if (rv != SCARD_S_SUCCESS)
        return tl::unexpected(AliroError::TRANSPORT_ERROR);

    response.resize(responseLen);
    return response;
}

bool PcscTransport::isOpen() const {
    return mIsOpen;
}

void PcscTransport::close() {
    if (mIsOpen) {
        mDisconnectFn(mHandle, SCARD_LEAVE_CARD);
        mIsOpen = false;
    }
}

}  // namespace aliro
