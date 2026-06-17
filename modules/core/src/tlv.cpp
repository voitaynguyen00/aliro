#include "aliro/core/tlv.h"

namespace aliro::tlv {

Result<Bytes> encode(uint32_t tag, ByteView value) {
    Bytes result;

    if (tag <= 0x7E) {
        result.push_back(static_cast<uint8_t>(tag));
    } else if (tag <= 0x7FFF) {
        result.push_back(static_cast<uint8_t>((tag >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(tag & 0xFF));
    } else {
        return tl::unexpected(AliroError::ENCODING_ERROR);
    }

    size_t len = value.size();
    if (len <= 127) {
        result.push_back(static_cast<uint8_t>(len));
    } else if (len <= 255) {
        result.push_back(0x81);
        result.push_back(static_cast<uint8_t>(len));
    } else if (len <= 65535) {
        result.push_back(0x82);
        result.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(len & 0xFF));
    } else {
        return tl::unexpected(AliroError::ENCODING_ERROR);
    }

    result.insert(result.end(), value.begin(), value.end());
    return result;
}

Result<TlvItem> decodeOne(ByteView data, size_t& bytesConsumed) {
    if (data.empty()) {
        return tl::unexpected(AliroError::DECODING_ERROR);
    }

    size_t pos = 0;
    TlvItem item;

    uint8_t first = data[pos++];
    if ((first & 0x1F) == 0x1F) {
        if (pos >= data.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        item.tag = (static_cast<uint32_t>(first) << 8) | data[pos++];
    } else {
        item.tag = first;
    }

    if (pos >= data.size()) return tl::unexpected(AliroError::DECODING_ERROR);

    size_t length = 0;
    uint8_t lenByte = data[pos++];
    if (lenByte <= 127) {
        length = lenByte;
    } else if (lenByte == 0x81) {
        if (pos >= data.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        length = data[pos++];
    } else if (lenByte == 0x82) {
        if (pos + 2 > data.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        length = (static_cast<size_t>(data[pos]) << 8) | data[pos + 1];
        pos += 2;
    } else {
        return tl::unexpected(AliroError::DECODING_ERROR);
    }

    if (pos + length > data.size()) return tl::unexpected(AliroError::DECODING_ERROR);

    item.value.assign(data.data() + pos, data.data() + pos + length);
    bytesConsumed = pos + length;
    return item;
}

Result<std::vector<TlvItem>> decodeAll(ByteView data) {
    std::vector<TlvItem> items;
    size_t offset = 0;
    while (offset < data.size()) {
        size_t consumed = 0;
        auto item = decodeOne(ByteView(data.data() + offset, data.size() - offset), consumed);
        if (!item) return tl::unexpected(item.error());
        items.push_back(std::move(*item));
        offset += consumed;
    }
    return items;
}

} // namespace aliro::tlv
