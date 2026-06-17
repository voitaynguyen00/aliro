#pragma once

#include <string>
#include <string_view>

#include "aliro/crypto/keyTypes.h"

namespace aliro {

// Public key — SubjectPublicKeyInfo DER (RFC 5480) / PEM "PUBLIC KEY"
Result<Bytes> publicKeyToDer(const EcPublicKey& key);
Result<EcPublicKey> publicKeyFromDer(ByteView der);
Result<std::string> publicKeyToPem(const EcPublicKey& key);
Result<EcPublicKey> publicKeyFromPem(std::string_view pem);

// Private key — SEC1 ECPrivateKey DER (RFC 5915) / PEM "EC PRIVATE KEY"
Result<Bytes> privateKeyToDer(const EcPrivateKey& key);
Result<EcPrivateKey> privateKeyFromDer(ByteView der);
Result<std::string> privateKeyToPem(const EcPrivateKey& key);
Result<EcPrivateKey> privateKeyFromPem(std::string_view pem);

}  // namespace aliro
