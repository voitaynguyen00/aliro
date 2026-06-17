#include "aliro/crypto/keySerializer.h"

#include <algorithm>

namespace aliro {

// ---------------------------------------------------------------------------
// Fixed DER byte sequences for P-256 (secp256r1).
//
// Public key — SubjectPublicKeyInfo (RFC 5480), 91 bytes total:
//   SEQUENCE(89) {
//     SEQUENCE(19) { OID ecPublicKey, OID secp256r1 }
//     BIT STRING(66) { 0x00, 04 || X(32) || Y(32) }
//   }
// ---------------------------------------------------------------------------
static constexpr uint8_t kSpkiPrefix[] = {
    0x30, 0x59,                                                  // SEQUENCE (89)
    0x30, 0x13,                                                  // SEQUENCE (19)
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,        // OID ecPublicKey
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  // OID secp256r1
    0x03, 0x42, 0x00,                                            // BIT STRING (66), no unused bits
};
static constexpr size_t kSpkiPrefixLen = sizeof(kSpkiPrefix);  // 26
static constexpr size_t kPublicKeyLen = 65;
static constexpr size_t kSpkiDerLen = kSpkiPrefixLen + kPublicKeyLen;  // 91

// ---------------------------------------------------------------------------
// Private key — SEC1 ECPrivateKey (RFC 5915), 51 bytes total:
//   SEQUENCE(49) {
//     INTEGER 1
//     OCTET STRING(32) { private scalar }
//     [0] EXPLICIT { OID secp256r1 }
//   }
// ---------------------------------------------------------------------------
static constexpr uint8_t kSec1Prefix[] = {
    0x30, 0x31,        // SEQUENCE (49)
    0x02, 0x01, 0x01,  // INTEGER 1
    0x04, 0x20,        // OCTET STRING (32)
};
static constexpr uint8_t kSec1Suffix[] = {
    0xa0, 0x0a,                                                  // [0] EXPLICIT (10)
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,  // OID secp256r1
};
static constexpr size_t kPrivateKeyLen = 32;
static constexpr size_t kSec1DerLen =
    sizeof(kSec1Prefix) + kPrivateKeyLen + sizeof(kSec1Suffix);  // 51

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------
static constexpr char kB64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64Encode(ByteView data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    for (; i + 2 < data.size(); i += 3) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | data[i + 2];
        out += kB64Chars[(v >> 18) & 0x3F];
        out += kB64Chars[(v >> 12) & 0x3F];
        out += kB64Chars[(v >> 6) & 0x3F];
        out += kB64Chars[(v >> 0) & 0x3F];
    }
    if (i + 1 == data.size()) {
        uint32_t v = uint32_t(data[i]) << 16;
        out += kB64Chars[(v >> 18) & 0x3F];
        out += kB64Chars[(v >> 12) & 0x3F];
        out += '=';
        out += '=';
    } else if (i + 2 == data.size()) {
        uint32_t v = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8);
        out += kB64Chars[(v >> 18) & 0x3F];
        out += kB64Chars[(v >> 12) & 0x3F];
        out += kB64Chars[(v >> 6) & 0x3F];
        out += '=';
    }
    return out;
}

static int b64Val(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static Bytes b64Decode(std::string_view s) {
    Bytes out;
    out.reserve((s.size() / 4) * 3);
    int buf = 0, bits = 0;
    for (char c : s) {
        if (c == '=')
            break;
        int v = b64Val(c);
        if (v < 0)
            continue;  // skip whitespace / newlines
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(uint8_t((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// PEM helpers
// ---------------------------------------------------------------------------
static std::string wrapPem(std::string_view label, ByteView der) {
    std::string b64 = b64Encode(der);
    std::string pem;
    pem.reserve(b64.size() + 64);
    pem += "-----BEGIN ";
    pem += label;
    pem += "-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) {
        pem += b64.substr(i, 64);
        pem += '\n';
    }
    pem += "-----END ";
    pem += label;
    pem += "-----\n";
    return pem;
}

static Result<Bytes> unwrapPem(std::string_view pem, std::string_view label) {
    std::string beginTag = "-----BEGIN ";
    beginTag += label;
    beginTag += "-----";
    std::string endTag = "-----END ";
    endTag += label;
    endTag += "-----";

    auto begin = pem.find(beginTag);
    if (begin == std::string_view::npos)
        return tl::unexpected(AliroError::DECODING_ERROR);
    begin += beginTag.size();

    auto end = pem.find(endTag, begin);
    if (end == std::string_view::npos)
        return tl::unexpected(AliroError::DECODING_ERROR);

    return b64Decode(pem.substr(begin, end - begin));
}

// ---------------------------------------------------------------------------
// Public key
// ---------------------------------------------------------------------------
Result<Bytes> publicKeyToDer(const EcPublicKey& key) {
    if (key.data.size() != kPublicKeyLen || key.data[0] != 0x04)
        return tl::unexpected(AliroError::ENCODING_ERROR);
    Bytes der;
    der.insert(der.end(), kSpkiPrefix, kSpkiPrefix + kSpkiPrefixLen);
    der.insert(der.end(), key.data.begin(), key.data.end());
    return der;
}

Result<EcPublicKey> publicKeyFromDer(ByteView der) {
    if (der.size() != kSpkiDerLen)
        return tl::unexpected(AliroError::DECODING_ERROR);
    if (!std::equal(kSpkiPrefix, kSpkiPrefix + kSpkiPrefixLen, der.begin()))
        return tl::unexpected(AliroError::DECODING_ERROR);
    EcPublicKey key;
    key.data.assign(der.begin() + kSpkiPrefixLen, der.end());
    if (key.data[0] != 0x04)
        return tl::unexpected(AliroError::DECODING_ERROR);
    return key;
}

Result<std::string> publicKeyToPem(const EcPublicKey& key) {
    auto der = publicKeyToDer(key);
    if (!der)
        return tl::unexpected(der.error());
    return wrapPem("PUBLIC KEY", *der);
}

Result<EcPublicKey> publicKeyFromPem(std::string_view pem) {
    auto der = unwrapPem(pem, "PUBLIC KEY");
    if (!der)
        return tl::unexpected(der.error());
    return publicKeyFromDer(*der);
}

// ---------------------------------------------------------------------------
// Private key
// ---------------------------------------------------------------------------
Result<Bytes> privateKeyToDer(const EcPrivateKey& key) {
    if (key.data.size() != kPrivateKeyLen)
        return tl::unexpected(AliroError::ENCODING_ERROR);
    Bytes der;
    der.insert(der.end(), kSec1Prefix, kSec1Prefix + sizeof(kSec1Prefix));
    der.insert(der.end(), key.data.begin(), key.data.end());
    der.insert(der.end(), kSec1Suffix, kSec1Suffix + sizeof(kSec1Suffix));
    return der;
}

Result<EcPrivateKey> privateKeyFromDer(ByteView der) {
    if (der.size() != kSec1DerLen)
        return tl::unexpected(AliroError::DECODING_ERROR);
    if (!std::equal(kSec1Prefix, kSec1Prefix + sizeof(kSec1Prefix), der.begin()))
        return tl::unexpected(AliroError::DECODING_ERROR);
    auto suffixStart = der.begin() + sizeof(kSec1Prefix) + kPrivateKeyLen;
    if (!std::equal(kSec1Suffix, kSec1Suffix + sizeof(kSec1Suffix), suffixStart))
        return tl::unexpected(AliroError::DECODING_ERROR);
    EcPrivateKey priv;
    priv.data.assign(der.begin() + sizeof(kSec1Prefix), suffixStart);
    return priv;
}

Result<std::string> privateKeyToPem(const EcPrivateKey& key) {
    auto der = privateKeyToDer(key);
    if (!der)
        return tl::unexpected(der.error());
    return wrapPem("EC PRIVATE KEY", *der);
}

Result<EcPrivateKey> privateKeyFromPem(std::string_view pem) {
    auto der = unwrapPem(pem, "EC PRIVATE KEY");
    if (!der)
        return tl::unexpected(der.error());
    return privateKeyFromDer(*der);
}

}  // namespace aliro
