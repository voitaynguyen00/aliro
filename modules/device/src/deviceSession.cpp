#include "aliro/device/deviceSession.h"

#include "aliro/core/accessDocument.h"
#include "aliro/core/log.h"
#include "aliro/core/protocol.h"
#include "aliro/core/tlv.h"

namespace aliro {

namespace {

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
                               const EcPrivateKey& deviceEphPriv,
                               const EcPublicKey&  readerEphPub,
                               ByteView readerNonce, ByteView deviceNonce) {
    auto secret = crypto.ecdhCompute(deviceEphPriv, readerEphPub);
    if (!secret) return tl::unexpected(secret.error());

    Bytes salt;
    salt.insert(salt.end(), readerNonce.begin(), readerNonce.end());
    salt.insert(salt.end(), deviceNonce.begin(), deviceNonce.end());

    static constexpr uint8_t kInfo[] = {'a','l','i','r','o','-','s','e','s','s','i','o','n','-','v','1'};
    return crypto.hkdfDerive(*secret, salt, kInfo, protocol::kAesKeySize);
}

// Parse short-form APDU data field: header[4] | Lc[1] | data[Lc].
Result<ByteView> apduDataField(ByteView cmd) {
    if (cmd.size() < 5) return tl::unexpected(AliroError::DECODING_ERROR);
    size_t lc = cmd[4];
    if (cmd.size() < 5 + lc) return tl::unexpected(AliroError::DECODING_ERROR);
    return ByteView(cmd.data() + 5, lc);
}

} // namespace

DeviceSession::DeviceSession(ICryptoProvider&    crypto,
                             const EcPrivateKey& devicePrivKey,
                             AccessDocument      accessDoc)
    : mCrypto(crypto)
    , mDevicePrivKey(devicePrivKey)
    , mAccessDoc(std::move(accessDoc))
    , mReaderEphemeralPub({})
    , mDeviceEphemeralPub({})
    , mReaderLongTermPub({})
{}

Result<Bytes> DeviceSession::handleSelect(ByteView /*commandData*/) {
    ALIRO_LOG_DEBUG("handleSelect: responding OK");
    return Bytes{0x90, 0x00};
}

Result<Bytes> DeviceSession::handleAuth0(ByteView commandData) {
    ALIRO_LOG_DEBUG("handleAuth0: processing AUTH0 command");
    auto dataResult = apduDataField(commandData);
    if (!dataResult) {
        ALIRO_LOG_ERROR("handleAuth0: APDU too short");
        return tl::unexpected(dataResult.error());
    }

    auto items = tlv::decodeAll(*dataResult);
    if (!items) {
        ALIRO_LOG_ERROR("handleAuth0: TLV decode failed");
        return tl::unexpected(items.error());
    }

    Bytes readerEphPubBytes, readerNonce, readerLongTermPubBytes;
    for (auto& item : *items) {
        if (item.tag == protocol::kTagEphemeralPublicKey)  readerEphPubBytes = item.value;
        else if (item.tag == protocol::kTagReaderNonce)    readerNonce = item.value;
        else if (item.tag == protocol::kTagReaderIdentifier) readerLongTermPubBytes = item.value;
    }
    if (readerEphPubBytes.size() != protocol::kEcPublicKeySize || readerNonce.empty() ||
        readerLongTermPubBytes.size() != protocol::kEcPublicKeySize) {
        ALIRO_LOG_WARN("handleAuth0: missing or malformed required TLV fields");
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    }

    mReaderEphemeralPub   = EcPublicKey{readerEphPubBytes};
    mReaderLongTermPub    = EcPublicKey{readerLongTermPubBytes};
    mReaderNonce          = readerNonce;

    // Generate device ephemeral key + nonce
    auto kp = mCrypto.generateKeyPair();
    if (!kp) return tl::unexpected(kp.error());
    mDeviceEphemeralKp  = *kp;
    mDeviceEphemeralPub = kp->pub;

    auto deviceNonceResult = mCrypto.randomBytes(16);
    if (!deviceNonceResult) return tl::unexpected(deviceNonceResult.error());
    mDeviceNonce = std::move(*deviceNonceResult);

    mTranscript = makeTranscript(readerEphPubBytes, readerNonce,
                                 kp->pub.data, mDeviceNonce);

    auto sig = mCrypto.sign(mTranscript, mDevicePrivKey);
    if (!sig) return tl::unexpected(sig.error());

    auto sk = deriveSessionKey(mCrypto, kp->priv, mReaderEphemeralPub,
                               readerNonce, mDeviceNonce);
    if (!sk) return tl::unexpected(sk.error());
    mSessionKey = std::move(*sk);
    ALIRO_LOG_INFO("handleAuth0: session key derived (%zu bytes)", mSessionKey.size());

    auto ephTlv   = tlv::encode(protocol::kTagEphemeralPublicKey, kp->pub.data);
    auto nonceTlv = tlv::encode(protocol::kTagDeviceNonce, mDeviceNonce);
    auto sigTlv   = tlv::encode(protocol::kTagSignature, sig->data);
    if (!ephTlv || !nonceTlv || !sigTlv) return tl::unexpected(AliroError::ENCODING_ERROR);

    Bytes response;
    response.insert(response.end(), ephTlv->begin(),   ephTlv->end());
    response.insert(response.end(), nonceTlv->begin(), nonceTlv->end());
    response.insert(response.end(), sigTlv->begin(),   sigTlv->end());
    response.push_back(0x90);
    response.push_back(0x00);
    return response;
}

Result<Bytes> DeviceSession::handleAuth1(ByteView commandData) {
    auto dataResult = apduDataField(commandData);
    if (!dataResult) return tl::unexpected(dataResult.error());

    auto items = tlv::decodeAll(*dataResult);
    if (!items) return tl::unexpected(items.error());

    Bytes readerSigBytes;
    for (auto& item : *items) {
        if (item.tag == protocol::kTagSignature) readerSigBytes = item.value;
    }
    if (readerSigBytes.size() != protocol::kSignatureSize || mTranscript.empty()) {
        ALIRO_LOG_WARN("handleAuth1: missing signature or AUTH0 not completed");
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    }

    auto sigOk = mCrypto.verify(mTranscript, Signature{readerSigBytes}, mReaderLongTermPub);
    if (!sigOk || !*sigOk) {
        ALIRO_LOG_WARN("handleAuth1: reader signature verification failed");
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    }
    ALIRO_LOG_INFO("handleAuth1: reader authenticated, sending AccessDocument");

    auto encoded = encodeAccessDocument(mAccessDoc);
    if (!encoded) return tl::unexpected(encoded.error());

    Bytes response = std::move(*encoded);
    response.push_back(0x90);
    response.push_back(0x00);
    return response;
}

} // namespace aliro
