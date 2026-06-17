#include "aliro/core/issuerAuth.h"

#include "aliro/core/protocol.h"

namespace aliro {

Result<Bytes> encodeIssuerSignedItem(const IssuerSignedItem& item) {
    cbor::Encoder enc;
    enc.beginMap(4);
    enc.addText(protocol::kSignedItemDigestId);
    enc.addUint(item.digestId);
    enc.addText(protocol::kSignedItemRandom);
    enc.addBytes(item.random);
    enc.addText(protocol::kSignedItemElementId);
    enc.addText(item.elementIdentifier);
    enc.addText(protocol::kSignedItemElementValue);
    enc.addBytes(item.elementValue);
    return enc.finish();
}

Result<IssuerSignedItem> decodeIssuerSignedItem(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count)
        return tl::unexpected(AliroError::DECODING_ERROR);

    IssuerSignedItem item;
    for (size_t i = 0; i < *count; ++i) {
        auto key = dec.getText();
        if (!key)
            return tl::unexpected(AliroError::DECODING_ERROR);

        if (*key == protocol::kSignedItemDigestId) {
            auto v = dec.getUint();
            if (!v)
                return tl::unexpected(AliroError::DECODING_ERROR);
            item.digestId = static_cast<uint32_t>(*v);
        } else if (*key == protocol::kSignedItemRandom) {
            auto v = dec.getBytes();
            if (!v)
                return tl::unexpected(AliroError::DECODING_ERROR);
            item.random = std::move(*v);
        } else if (*key == protocol::kSignedItemElementId) {
            auto v = dec.getText();
            if (!v)
                return tl::unexpected(AliroError::DECODING_ERROR);
            item.elementIdentifier = std::move(*v);
        } else if (*key == protocol::kSignedItemElementValue) {
            auto v = dec.getBytes();
            if (!v)
                return tl::unexpected(AliroError::DECODING_ERROR);
            item.elementValue = std::move(*v);
        } else {
            if (!dec.skip())
                return tl::unexpected(AliroError::DECODING_ERROR);
        }
    }
    return item;
}

Result<Bytes> encodeIssuerAuth(const IssuerAuth& auth) {
    // COSE_Sign1 = [protected, unprotected, payload, signature]
    cbor::Encoder enc;
    enc.beginArray(4);
    enc.addBytes(auth.protectedHeader);
    enc.addBytes(auth.unprotectedHeader);
    enc.addBytes(auth.payload);
    enc.addBytes(auth.signature);
    return enc.finish();
}

Result<IssuerAuth> decodeIssuerAuth(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getArraySize();
    if (!count)
        return tl::unexpected(AliroError::DECODING_ERROR);
    if (*count != 4)
        return tl::unexpected(AliroError::DECODING_ERROR);

    IssuerAuth auth;

    auto protHdr = dec.getBytes();
    if (!protHdr)
        return tl::unexpected(AliroError::DECODING_ERROR);
    auth.protectedHeader = std::move(*protHdr);

    auto unprotHdr = dec.getBytes();
    if (!unprotHdr)
        return tl::unexpected(AliroError::DECODING_ERROR);
    auth.unprotectedHeader = std::move(*unprotHdr);

    auto payload = dec.getBytes();
    if (!payload)
        return tl::unexpected(AliroError::DECODING_ERROR);
    auth.payload = std::move(*payload);

    auto sig = dec.getBytes();
    if (!sig)
        return tl::unexpected(AliroError::DECODING_ERROR);
    if (sig->size() != protocol::kSignatureSize) {
        return tl::unexpected(AliroError::INVALID_MESSAGE);
    }
    auth.signature = std::move(*sig);

    return auth;
}

}  // namespace aliro
