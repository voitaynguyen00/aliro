#pragma once

#include <functional>

#include "aliro/transport/iTransport.h"

namespace aliro {

/// Synchronous in-memory transport for unit testing.
/// The handler simulates the remote endpoint: given a command frame, return a response frame.
class SimTransport : public ITransport {
public:
    using Handler = std::function<Result<Bytes>(ByteView)>;

    explicit SimTransport(Handler handler);

    Result<Bytes> transceive(ByteView command) override;
    bool isOpen() const override;
    void close() override;

private:
    Handler mHandler;
    bool mIsOpen{true};
};

}  // namespace aliro
