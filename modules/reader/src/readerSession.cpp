#include "aliro/reader/readerSession.h"

#include "aliro/core/apdu.h"
#include "aliro/core/protocol.h"
#include "aliro/core/tlv.h"

namespace aliro {

namespace {

// Transcript: readerEphPub(65) || readerNonce(16) || deviceEphPub(65) || deviceNonce(16) = 162 B
Bytes makeTranscript(ByteView readerEphPub, ByteView readerNonce,
                     ByteView deviceEphPub, ByteView deviceNonce) {
    Bytes t;
    t.reserve(162);
    t.insert(t.end(), readerEphPub.begin(),  readerEphPub.end());
    t.insert(t.end(), readerNonce.begin(),   readerNonce.end());
    t.insert(t.end(), deviceEphPub.begin(),  deviceEphPub.end());
    t.insert(t.end(), deviceNonce.begin(),   deviceNonce.end());
    return t;
}

Result<Bytes> deriveSessionKey(ICryptoProvider& crypto,
                               const EcPrivateKey& readerEphPriv,
                               const EcPublicKey& deviceEphPub,
                               ByteView readerNonce, ByteView deviceNonce) {
    auto secret = crypto.ecdhCompute(readerEphPriv, deviceEphPub);
    if (!secret) return tl::unexpected(secret.error());

    Bytes salt;
    salt.insert(salt.end(), readerNonce.begin(), readerNonce.end());
    salt.insert(salt.end(), deviceNonce.begin(), deviceNonce.end());

    static constexpr uint8_t kInfo[] = {'a','l','i','r','o','-','s','e','s','s','i','o','n','-','v','1'};
    return crypto.hkdfDerive(*secret, salt, kInfo, protocol::kAesKeySize);
}

} // namespace

ReaderSession::ReaderSession(ICryptoProvider& crypto, ITransport& transport)
    : mCrypto(crypto), mTransport(transport) {}

Result<AuthResult> ReaderSession::authenticate(const EcPrivateKey& readerPrivKey,
                                                const EcPublicKey&  devicePubKey) {
    // ---- AUTH0 --------------------------------------------------------
    auto ephKp = mCrypto.generateKeyPair();
    if (!ephKp) return tl::unexpected(ephKp.error());

    auto readerNonceResult = mCrypto.randomBytes(16);
    if (!readerNonceResult) return tl::unexpected(readerNonceResult.error());
    Bytes readerNonce = std::move(*readerNonceResult);

    auto ephPubTlv  = tlv::encode(protocol::kTagEphemeralPublicKey, ephKp->pub.data);
    auto nonceTlv   = tlv::encode(protocol::kTagReaderNonce, readerNonce);
    if (!ephPubTlv || !nonceTlv) return tl::unexpected(AliroError::ENCODING_ERROR);

    Bytes auth0Data;
    auth0Data.insert(auth0Data.end(), ephPubTlv->begin(), ephPubTlv->end());
    auth0Data.insert(auth0Data.end(), nonceTlv->begin(),  nonceTlv->end());

    auto auth0Cmd = apdu::buildCommand(protocol::kAliroCla, protocol::kInsAuth0,
                                       0x00, 0x00, auth0Data);
    auto auth0Raw = mTransport.transceive(auth0Cmd);
    if (!auth0Raw) return tl::unexpected(auth0Raw.error());

    auto auth0Resp = apdu::parseResponse(*auth0Raw);
    if (!auth0Resp) return tl::unexpected(auth0Resp.error());

    auto items = tlv::decodeAll(*auth0Resp);
    if (!items) return tl::unexpected(items.error());

    Bytes deviceEphPubBytes, deviceNonce, deviceSig;
    for (auto& item : *items) {
        if (item.tag == protocol::kTagEphemeralPublicKey)  deviceEphPubBytes = item.value;
        else if (item.tag == protocol::kTagDeviceNonce)    deviceNonce = item.value;
        else if (item.tag == protocol::kTagSignature)      deviceSig = item.value;
    }
    if (deviceEphPubBytes.size() != protocol::kEcPublicKeySize ||
        deviceNonce.empty() || deviceSig.size() != protocol::kSignatureSize)
        return tl::unexpected(AliroError::INVALID_MESSAGE);

    EcPublicKey deviceEphPub{deviceEphPubBytes};
    Bytes transcript = makeTranscript(ephKp->pub.data, readerNonce,
                                      deviceEphPubBytes, deviceNonce);

    auto sigOk = mCrypto.verify(transcript, Signature{deviceSig}, devicePubKey);
    if (!sigOk || !*sigOk) return tl::unexpected(AliroError::INVALID_MESSAGE);

    auto sessionKey = deriveSessionKey(mCrypto, ephKp->priv, deviceEphPub,
                                       readerNonce, deviceNonce);
    if (!sessionKey) return tl::unexpected(sessionKey.error());

    // ---- AUTH1 --------------------------------------------------------
    auto readerSigResult = mCrypto.sign(transcript, readerPrivKey);
    if (!readerSigResult) return tl::unexpected(readerSigResult.error());

    auto sigTlv = tlv::encode(protocol::kTagSignature, readerSigResult->data);
    if (!sigTlv) return tl::unexpected(AliroError::ENCODING_ERROR);

    auto auth1Cmd = apdu::buildCommand(protocol::kAliroCla, protocol::kInsAuth1,
                                       0x00, 0x00, *sigTlv);
    auto auth1Raw = mTransport.transceive(auth1Cmd);
    if (!auth1Raw) return tl::unexpected(auth1Raw.error());

    auto auth1Resp = apdu::parseResponse(*auth1Raw);
    if (!auth1Resp) return tl::unexpected(auth1Resp.error());

    auto accessDoc = decodeAccessDocument(*auth1Resp);
    if (!accessDoc) return tl::unexpected(accessDoc.error());

    return AuthResult{std::move(*accessDoc), std::move(*sessionKey)};
}

} // namespace aliro
