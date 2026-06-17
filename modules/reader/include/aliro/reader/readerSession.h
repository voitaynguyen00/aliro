#pragma once

#include "aliro/core/accessDocument.h"
#include "aliro/core/types.h"
#include "aliro/crypto/iCryptoProvider.h"
#include "aliro/transport/iTransport.h"

namespace aliro {

/// Result of a successful Aliro authentication.
struct AuthResult {
    AccessDocument accessDoc;
    Bytes sessionKey;  ///< Derived AES-128 session key.
};

/// Executes the two-step Aliro reader authentication flow over an ITransport.
///
/// Step 1 (AUTH0): Generates an ephemeral key pair and nonce, sends them to
///   the device, and receives the device's ephemeral key, nonce, and signature.
///   Verifies the device signature.
///
/// Step 2 (AUTH1): Derives a session key via ECDH+HKDF, signs the transcript,
///   and sends the signature to the device. Receives and returns the AccessDocument.
class ReaderSession {
public:
    ReaderSession(ICryptoProvider& crypto, ITransport& transport);

    /// Run the SELECT → AUTH0 → AUTH1 exchange.
    /// @param readerKp      Reader's long-term key pair (pub sent in AUTH0; priv signs AUTH1
    /// transcript).
    /// @param devicePubKey  Expected device long-term public key (for AUTH0 signature
    /// verification).
    Result<AuthResult> authenticate(const EcKeyPair& readerKp, const EcPublicKey& devicePubKey);

private:
    ICryptoProvider& mCrypto;
    ITransport& mTransport;
};

}  // namespace aliro
