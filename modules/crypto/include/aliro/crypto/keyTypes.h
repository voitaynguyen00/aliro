#pragma once

#include "aliro/core/types.h"

namespace aliro {

/// Uncompressed P-256 public key point (04 || X || Y), 65 bytes.
struct EcPublicKey {
    Bytes data;
};

/// P-256 private scalar, 32 bytes (big-endian).
struct EcPrivateKey {
    Bytes data;
};

/// A P-256 key pair.
struct EcKeyPair {
    EcPublicKey pub;
    EcPrivateKey priv;
};

/// AES-128 session key, 16 bytes.
struct SessionKey {
    Bytes data;
};

/// ECDSA P-256 raw signature: r || s, 64 bytes.
struct Signature {
    Bytes data;
};

}  // namespace aliro
