#pragma once

#include "aliro/core/types.h"

namespace aliro {

/// Abstraction over a request-response transport channel (NFC, BLE, UWB, or Sim).
/// The Reader always initiates; the Device always responds.
class ITransport {
public:
    virtual ~ITransport() = default;

    /// Send a command frame and return the response frame.
    virtual Result<Bytes> transceive(ByteView command) = 0;

    /// Returns true while the transport link is open.
    virtual bool isOpen() const = 0;

    /// Close the transport channel.
    virtual void close() = 0;
};

}  // namespace aliro
