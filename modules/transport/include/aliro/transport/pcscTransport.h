#pragma once

#if defined(_WIN32)
#  include <winscard.h>
#else
// wintypes.h supplies DWORD/LONG/LPCBYTE etc.; winscard.h on some platforms
// (macOS PCSC framework) does not pull it in automatically.
#  include <PCSC/wintypes.h>
#  include <PCSC/winscard.h>
#endif

#include "aliro/transport/iTransport.h"

namespace aliro {

/// PC/SC transport wrapping an active SCardConnect handle.
///
/// Caller owns the PC/SC lifecycle (SCardEstablishContext → SCardConnect → construct
/// this object → use → destruct → SCardReleaseContext).  close() issues
/// SCardDisconnect(SCARD_LEAVE_CARD) and marks the transport closed.
///
/// Inject transmitFn / disconnectFn to substitute mocks in unit tests —
/// the defaults forward to the real PC/SC API.
class PcscTransport : public ITransport {
public:
    using TransmitFn = LONG (*)(SCARDHANDLE, const SCARD_IO_REQUEST*, LPCBYTE, DWORD,
                                LPSCARD_IO_REQUEST, LPBYTE, LPDWORD);
    using DisconnectFn = LONG (*)(SCARDHANDLE, DWORD);

    explicit PcscTransport(SCARDHANDLE handle, DWORD protocol,
                           TransmitFn transmitFn = SCardTransmit,
                           DisconnectFn disconnectFn = SCardDisconnect);

    ~PcscTransport() override;

    Result<Bytes> transceive(ByteView command) override;
    bool isOpen() const override;
    void close() override;

private:
    SCARDHANDLE mHandle;
    DWORD mProtocol;
    TransmitFn mTransmitFn;
    DisconnectFn mDisconnectFn;
    bool mIsOpen{true};
};

}  // namespace aliro
