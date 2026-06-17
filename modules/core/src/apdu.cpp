#include "aliro/core/apdu.h"

namespace aliro::apdu {

Bytes buildCommand(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, ByteView data,
                   bool expectResponse) {
    Bytes cmd;
    cmd.reserve(5 + data.size() + (expectResponse ? 1 : 0));
    cmd.push_back(cla);
    cmd.push_back(ins);
    cmd.push_back(p1);
    cmd.push_back(p2);
    if (!data.empty()) {
        if (data.size() <= 0xFF) {
            cmd.push_back(static_cast<uint8_t>(data.size()));
        } else {
            // Extended length
            cmd.push_back(0x00);
            cmd.push_back(static_cast<uint8_t>(data.size() >> 8));
            cmd.push_back(static_cast<uint8_t>(data.size() & 0xFF));
        }
        cmd.insert(cmd.end(), data.begin(), data.end());
    }
    if (expectResponse) {
        if (data.size() > 0xFF) {
            cmd.push_back(0x00);  // extended Le
            cmd.push_back(0x00);
        } else {
            cmd.push_back(0x00);  // Le: max response
        }
    }
    return cmd;
}

uint16_t statusWord(ByteView response) {
    if (response.size() < 2)
        return 0;
    return static_cast<uint16_t>((static_cast<uint16_t>(response[response.size() - 2]) << 8) |
                                 response[response.size() - 1]);
}

Result<Bytes> parseResponse(ByteView response) {
    if (response.size() < 2)
        return tl::unexpected(AliroError::DECODING_ERROR);
    uint16_t sw = statusWord(response);
    if (sw != 0x9000)
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    return Bytes(response.begin(), response.end() - 2);
}

}  // namespace aliro::apdu
