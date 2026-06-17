#pragma once

#include "aliro/core/accessDocument.h"
#include "aliro/core/types.h"
#include "aliro/crypto/iCryptoProvider.h"
#include "aliro/transport/iTransport.h"

namespace aliro {

/// Result of a successful Aliro authentication.
struct AuthResult {
    AccessDocument accessDoc;
    Bytes          sessionKey; ///< Derived AES-128 session key.
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

    /// Run the full AUTH0 → AUTH1 exchange.
    /// @param readerPrivKey   Reader's long-term private key for signing.
    /// @param readerPubKey    Reader's long-term public key (sent to device).
    /// @param devicePubKey    Expected device long-term public key (for AUTH0 verification).
    Result<AuthResult> authenticate(const EcPrivateKey& readerPrivKey,
                                    const EcPublicKey&  devicePubKey);

private:
    ICryptoProvider& mCrypto;
    ITransport&      mTransport;
};

} // namespace aliro
