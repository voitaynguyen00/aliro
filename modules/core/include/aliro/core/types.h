#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>
#include <tl/expected.hpp>

namespace aliro {

using Bytes    = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;

enum class AliroError {
    CRYPTO_FAILURE,
    INVALID_MESSAGE,
    INVALID_STATE,
    UNSUPPORTED_VERSION,
    TRANSPORT_ERROR,
    ACCESS_DENIED,
    DOCUMENT_EXPIRED,
    REVOCATION_CHECK_FAILED,
    ENCODING_ERROR,
    DECODING_ERROR,
    NOT_FOUND,
};

template<typename T>
using Result = tl::expected<T, AliroError>;

} // namespace aliro
