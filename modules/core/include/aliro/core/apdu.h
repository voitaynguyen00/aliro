#pragma once

#include <cstdint>

#include "aliro/core/types.h"

namespace aliro::apdu {

/// Build a command APDU (CLA INS P1 P2 [Lc data] [Le]).
/// If data is empty, no Lc/data field is written. Le=0x00 requests max response.
Bytes buildCommand(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, ByteView data = {},
                   bool expectResponse = true);

/// Extract the data field from a response APDU.
/// Returns DECODING_ERROR if the response is shorter than 2 bytes.
/// Returns INVALID_MESSAGE if SW1/SW2 is not 0x9000.
Result<Bytes> parseResponse(ByteView response);

/// Read SW1/SW2 from the last two bytes of a response. Returns 0 on too-short input.
uint16_t statusWord(ByteView response);

}  // namespace aliro::apdu
