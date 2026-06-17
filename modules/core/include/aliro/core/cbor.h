#pragma once

#include "aliro/core/types.h"
#include <string_view>

namespace aliro::cbor {

enum class MajorType : uint8_t {
    UINT   = 0,
    INT    = 1,
    BYTES  = 2,
    TEXT   = 3,
    ARRAY  = 4,
    MAP    = 5,
    TAG    = 6,
    SIMPLE = 7,
};

/// Minimal CBOR encoder producing core-deterministic output (RFC 8949 §4.2.1).
class Encoder {
public:
    void addUint(uint64_t value);
    void addInt(int64_t value);
    void addBytes(ByteView data);
    void addText(std::string_view text);
    void addBool(bool value);
    void addNull();
    void addTag(uint64_t tag);
    void beginArray(size_t count);
    void beginMap(size_t count);

    Bytes finish();

private:
    Bytes mBuffer;
    void encodeHead(MajorType major, uint64_t value);
};

/// Streaming CBOR decoder.
class Decoder {
public:
    explicit Decoder(ByteView data);

    bool isAtEnd() const;
    Result<MajorType> peekMajorType() const;

    Result<uint64_t>    getUint();
    Result<int64_t>     getInt();
    Result<Bytes>       getBytes();
    Result<std::string> getText();
    Result<bool>        getBool();
    Result<void>        getNull();
    Result<uint64_t>    getTag();
    Result<size_t>      getArraySize();
    Result<size_t>      getMapSize();
    Result<void>        skip();

    size_t bytesConsumed() const;

private:
    ByteView mData;
    size_t   mPos{0};

    Result<uint64_t> decodeHead(uint8_t& outMajorType);
};

} // namespace aliro::cbor
