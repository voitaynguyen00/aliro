#pragma once

#include <cstdint>
#include <vector>

#include "aliro/core/types.h"

namespace aliro::tlv {

struct TlvItem {
    uint32_t tag;
    Bytes value;
};

/// Encode a single DER-TLV item.
Result<Bytes> encode(uint32_t tag, ByteView value);

/// Decode one DER-TLV item from the start of data.
/// On success, bytesConsumed is set to the number of bytes read.
Result<TlvItem> decodeOne(ByteView data, size_t& bytesConsumed);

/// Decode all consecutive DER-TLV items from data.
Result<std::vector<TlvItem>> decodeAll(ByteView data);

}  // namespace aliro::tlv
