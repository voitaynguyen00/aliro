#include "aliro/device/deviceSession.h"

#include "aliro/core/accessDocument.h"
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

} // namespace

DeviceSession::DeviceSession(ICryptoProvider&    crypto,
                             const EcPrivateKey& devicePrivKey,
                             AccessDocument      accessDoc)
    : mCrypto(crypto)
    , mDevicePrivKey(devicePrivKey)
    , mAccessDoc(std::move(accessDoc))
    , mReaderEphemeralPub({})
    , mDeviceEphemeralPub({})
{}

Result<Bytes> DeviceSession::handleAuth0(ByteView commandData) {
    // Parse APDU: strip CLA INS P1 P2 Lc, keep data field
    // commandData here is the raw APDU command including header
    if (commandData.size() < 5) return tl::unexpected(AliroError::DECODING_ERROR);

    // Find Lc and data: header is 4 bytes, Lc at byte 4
    size_t headerEnd = 4;
    size_t lc = commandData[headerEnd];
    size_t dataStart = headerEnd + 1;
    if (commandData.size() < dataStart + lc)
        return tl::unexpected(AliroError::DECODING_ERROR);

    ByteView data(commandData.data() + dataStart, lc);
    auto items = tlv::decodeAll(data);
    if (!items) return tl::unexpected(items.error());

    Bytes readerEphPubBytes, readerNonce;
    for (auto& item : *items) {
        if (item.tag == protocol::kTagEphemeralPublicKey) readerEphPubBytes = item.value;
        else if (item.tag == protocol::kTagReaderNonce)   readerNonce = item.value;
    }
    if (readerEphPubBytes.size() != protocol::kEcPublicKeySize || readerNonce.empty())
        return tl::unexpected(AliroError::INVALID_MESSAGE);

    mReaderEphemeralPub = EcPublicKey{readerEphPubBytes};
    mReaderNonce = readerNonce;

    // Generate device ephemeral key + nonce
    auto kp = mCrypto.generateKeyPair();
    if (!kp) return tl::unexpected(kp.error());
    mDeviceEphemeralKp = *kp;
    mDeviceEphemeralPub = kp->pub;

    auto deviceNonceResult = mCrypto.randomBytes(16);
    if (!deviceNonceResult) return tl::unexpected(deviceNonceResult.error());
    mDeviceNonce = std::move(*deviceNonceResult);

    // Compute transcript and sign
    Bytes transcript = makeTranscript(readerEphPubBytes, readerNonce,
                                      kp->pub.data, mDeviceNonce);
    auto sig = mCrypto.sign(transcript, mDevicePrivKey);
    if (!sig) return tl::unexpected(sig.error());

    // Derive session key
    auto sk = deriveSessionKey(mCrypto, kp->priv, mReaderEphemeralPub,
                               readerNonce, mDeviceNonce);
    if (!sk) return tl::unexpected(sk.error());
    mSessionKey = std::move(*sk);

    // Build response data
    auto ephTlv  = tlv::encode(protocol::kTagEphemeralPublicKey, kp->pub.data);
    auto nonceTlv = tlv::encode(protocol::kTagDeviceNonce, mDeviceNonce);
    auto sigTlv   = tlv::encode(protocol::kTagSignature, sig->data);
    if (!ephTlv || !nonceTlv || !sigTlv) return tl::unexpected(AliroError::ENCODING_ERROR);

    Bytes response;
    response.insert(response.end(), ephTlv->begin(),   ephTlv->end());
    response.insert(response.end(), nonceTlv->begin(), nonceTlv->end());
    response.insert(response.end(), sigTlv->begin(),   sigTlv->end());
    // Append SW 0x9000
    response.push_back(0x90);
    response.push_back(0x00);
    return response;
}

Result<Bytes> DeviceSession::handleAuth1(ByteView commandData) {
    // Strip APDU header (4 bytes) + Lc (1 byte)
    if (commandData.size() < 5) return tl::unexpected(AliroError::DECODING_ERROR);
    size_t lc = commandData[4];
    if (commandData.size() < 5 + lc) return tl::unexpected(AliroError::DECODING_ERROR);

    ByteView data(commandData.data() + 5, lc);
    auto items = tlv::decodeAll(data);
    if (!items) return tl::unexpected(items.error());

    // Minimal check: signature tag must be present and correct size
    bool hasSig = false;
    for (auto& item : *items) {
        if (item.tag == protocol::kTagSignature && item.value.size() == protocol::kSignatureSize)
            hasSig = true;
    }
    if (!hasSig) return tl::unexpected(AliroError::INVALID_MESSAGE);

    // Encode the AccessDocument and return it with SW 0x9000
    auto encoded = encodeAccessDocument(mAccessDoc);
    if (!encoded) return tl::unexpected(encoded.error());

    Bytes response = std::move(*encoded);
    response.push_back(0x90);
    response.push_back(0x00);
    return response;
}

} // namespace aliro
