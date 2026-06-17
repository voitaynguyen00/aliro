#include "aliro/core/cbor.h"

namespace aliro::cbor {

// --- Encoder ---

void Encoder::encodeHead(MajorType major, uint64_t value) {
    uint8_t majorByte = static_cast<uint8_t>(major) << 5;
    if (value <= 23) {
        mBuffer.push_back(majorByte | static_cast<uint8_t>(value));
    } else if (value <= 0xFF) {
        mBuffer.push_back(majorByte | 24);
        mBuffer.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFF) {
        mBuffer.push_back(majorByte | 25);
        mBuffer.push_back(static_cast<uint8_t>(value >> 8));
        mBuffer.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFFFFFF) {
        mBuffer.push_back(majorByte | 26);
        mBuffer.push_back(static_cast<uint8_t>(value >> 24));
        mBuffer.push_back(static_cast<uint8_t>(value >> 16));
        mBuffer.push_back(static_cast<uint8_t>(value >> 8));
        mBuffer.push_back(static_cast<uint8_t>(value));
    } else {
        mBuffer.push_back(majorByte | 27);
        for (int i = 7; i >= 0; --i) {
            mBuffer.push_back(static_cast<uint8_t>(value >> (8 * i)));
        }
    }
}

void Encoder::addUint(uint64_t value)  { encodeHead(MajorType::UINT, value); }
void Encoder::addTag(uint64_t tag)     { encodeHead(MajorType::TAG, tag); }
void Encoder::beginArray(size_t count) { encodeHead(MajorType::ARRAY, count); }
void Encoder::beginMap(size_t count)   { encodeHead(MajorType::MAP, count); }
void Encoder::addBool(bool value)      { mBuffer.push_back(value ? 0xF5 : 0xF4); }
void Encoder::addNull()                { mBuffer.push_back(0xF6); }

void Encoder::addInt(int64_t value) {
    if (value >= 0) {
        encodeHead(MajorType::UINT, static_cast<uint64_t>(value));
    } else {
        encodeHead(MajorType::INT, static_cast<uint64_t>(-1 - value));
    }
}

void Encoder::addBytes(ByteView data) {
    encodeHead(MajorType::BYTES, data.size());
    mBuffer.insert(mBuffer.end(), data.begin(), data.end());
}

void Encoder::addText(std::string_view text) {
    encodeHead(MajorType::TEXT, text.size());
    mBuffer.insert(mBuffer.end(), text.begin(), text.end());
}

Bytes Encoder::finish() { return std::move(mBuffer); }

// --- Decoder ---

Decoder::Decoder(ByteView data) : mData(data), mPos(0) {}

bool Decoder::isAtEnd() const { return mPos >= mData.size(); }
size_t Decoder::bytesConsumed() const { return mPos; }

Result<MajorType> Decoder::peekMajorType() const {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    return static_cast<MajorType>(mData[mPos] >> 5);
}

Result<uint64_t> Decoder::decodeHead(uint8_t& outMajorType) {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    uint8_t byte = mData[mPos++];
    outMajorType = byte >> 5;
    uint8_t info = byte & 0x1F;

    if (info <= 23) return static_cast<uint64_t>(info);

    if (info == 24) {
        if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        return static_cast<uint64_t>(mData[mPos++]);
    }
    if (info == 25) {
        if (mPos + 2 > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        uint64_t v = (static_cast<uint64_t>(mData[mPos]) << 8) | mData[mPos + 1];
        mPos += 2;
        return v;
    }
    if (info == 26) {
        if (mPos + 4 > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        uint64_t v = 0;
        for (int i = 3; i >= 0; --i) v |= static_cast<uint64_t>(mData[mPos++]) << (8 * i);
        return v;
    }
    if (info == 27) {
        if (mPos + 8 > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
        uint64_t v = 0;
        for (int i = 7; i >= 0; --i) v |= static_cast<uint64_t>(mData[mPos++]) << (8 * i);
        return v;
    }
    return tl::unexpected(AliroError::DECODING_ERROR);
}

Result<uint64_t> Decoder::getUint() {
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());
    if (major != 0) return tl::unexpected(AliroError::DECODING_ERROR);
    return *val;
}

Result<int64_t> Decoder::getInt() {
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());
    if (major == 0) return static_cast<int64_t>(*val);
    if (major == 1) return static_cast<int64_t>(-1 - static_cast<int64_t>(*val));
    return tl::unexpected(AliroError::DECODING_ERROR);
}

Result<Bytes> Decoder::getBytes() {
    uint8_t major = 0;
    auto lenResult = decodeHead(major);
    if (!lenResult) return tl::unexpected(lenResult.error());
    if (major != 2) return tl::unexpected(AliroError::DECODING_ERROR);
    size_t len = static_cast<size_t>(*lenResult);
    if (mPos + len > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    Bytes result(mData.data() + mPos, mData.data() + mPos + len);
    mPos += len;
    return result;
}

Result<std::string> Decoder::getText() {
    uint8_t major = 0;
    auto lenResult = decodeHead(major);
    if (!lenResult) return tl::unexpected(lenResult.error());
    if (major != 3) return tl::unexpected(AliroError::DECODING_ERROR);
    size_t len = static_cast<size_t>(*lenResult);
    if (mPos + len > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    std::string result(reinterpret_cast<const char*>(mData.data() + mPos), len);
    mPos += len;
    return result;
}

Result<bool> Decoder::getBool() {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    uint8_t byte = mData[mPos++];
    if (byte == 0xF5) return true;
    if (byte == 0xF4) return false;
    return tl::unexpected(AliroError::DECODING_ERROR);
}

Result<void> Decoder::getNull() {
    if (mPos >= mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
    if (mData[mPos++] != 0xF6) return tl::unexpected(AliroError::DECODING_ERROR);
    return {};
}

Result<uint64_t> Decoder::getTag() {
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());
    if (major != 6) return tl::unexpected(AliroError::DECODING_ERROR);
    return *val;
}

Result<size_t> Decoder::getArraySize() {
    uint8_t major = 0;
    auto count = decodeHead(major);
    if (!count) return tl::unexpected(count.error());
    if (major != 4) return tl::unexpected(AliroError::DECODING_ERROR);
    return static_cast<size_t>(*count);
}

Result<size_t> Decoder::getMapSize() {
    uint8_t major = 0;
    auto count = decodeHead(major);
    if (!count) return tl::unexpected(count.error());
    if (major != 5) return tl::unexpected(AliroError::DECODING_ERROR);
    return static_cast<size_t>(*count);
}

Result<void> Decoder::skip() {
    if (isAtEnd()) return tl::unexpected(AliroError::DECODING_ERROR);
    uint8_t major = 0;
    auto val = decodeHead(major);
    if (!val) return tl::unexpected(val.error());

    switch (static_cast<MajorType>(major)) {
        case MajorType::UINT:
        case MajorType::INT:
            return {};
        case MajorType::SIMPLE:
            return {};
        case MajorType::BYTES:
        case MajorType::TEXT: {
            size_t len = static_cast<size_t>(*val);
            if (mPos + len > mData.size()) return tl::unexpected(AliroError::DECODING_ERROR);
            mPos += len;
            return {};
        }
        case MajorType::ARRAY: {
            for (uint64_t i = 0; i < *val; ++i) {
                auto r = skip();
                if (!r) return r;
            }
            return {};
        }
        case MajorType::MAP: {
            for (uint64_t i = 0; i < *val * 2; ++i) {
                auto r = skip();
                if (!r) return r;
            }
            return {};
        }
        case MajorType::TAG:
            return skip();
        default:
            return tl::unexpected(AliroError::DECODING_ERROR);
    }
}

} // namespace aliro::cbor
