#pragma once

#include "aliro/core/accessDocument.h"
#include "aliro/core/types.h"
#include "aliro/crypto/iCryptoProvider.h"

namespace aliro {

/// Processes a single Aliro authentication exchange from the device (responder) side.
///
/// Usage:
///   DeviceSession session(crypto, devicePrivKey, devicePubKey, accessDoc);
///   auto auth0Response = session.handleAuth0(auth0Command);
///   auto auth1Response = session.handleAuth1(auth1Command);
class DeviceSession {
public:
    DeviceSession(ICryptoProvider&    crypto,
                  const EcPrivateKey& devicePrivKey,
                  AccessDocument      accessDoc);

    /// Process the AUTH0 command and return a response APDU body (without SW).
    Result<Bytes> handleAuth0(ByteView commandData);

    /// Process the AUTH1 command and return a response APDU body (without SW).
    Result<Bytes> handleAuth1(ByteView commandData);

    /// Returns the derived session key after AUTH0 completes.
    const Bytes& sessionKey() const { return mSessionKey; }

private:
    ICryptoProvider&    mCrypto;
    const EcPrivateKey& mDevicePrivKey;
    AccessDocument      mAccessDoc;

    // Set during AUTH0 processing
    EcPublicKey mReaderEphemeralPub;
    EcPublicKey mDeviceEphemeralPub;
    Bytes       mReaderNonce;
    Bytes       mDeviceNonce;
    Bytes       mSessionKey;
    EcKeyPair   mDeviceEphemeralKp;
};

} // namespace aliro
