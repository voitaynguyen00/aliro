#include "aliro/transport/simTransport.h"

namespace aliro {

SimTransport::SimTransport(Handler handler) : mHandler(std::move(handler)) {}

Result<Bytes> SimTransport::transceive(ByteView command) {
    if (!mIsOpen)
        return tl::unexpected(AliroError::TRANSPORT_ERROR);
    return mHandler(command);
}

bool SimTransport::isOpen() const { return mIsOpen; }

void SimTransport::close() { mIsOpen = false; }

} // namespace aliro
