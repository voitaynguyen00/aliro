#include "aliro/core/accessDocument.h"
#include "aliro/core/cbor.h"

namespace aliro {

Result<Bytes> encodeAccessDocument(const AccessDocument& doc) {
    auto issuerAuthBytes = encodeIssuerAuth(doc.issuerAuth);
    if (!issuerAuthBytes) return tl::unexpected(issuerAuthBytes.error());

    cbor::Encoder enc;
    size_t fieldCount = 2 + (doc.nameSpaces.empty() ? 0 : 1);
    enc.beginMap(fieldCount);

    enc.addText("docType");
    enc.addText(doc.docType);

    enc.addText("issuerAuth");
    enc.addBytes(*issuerAuthBytes);

    if (!doc.nameSpaces.empty()) {
        enc.addText("nameSpaces");
        enc.beginMap(doc.nameSpaces.size());
        for (const auto& ns : doc.nameSpaces) {
            enc.addText(ns.nameSpace);
            enc.beginArray(ns.issuerSignedItems.size());
            for (const auto& item : ns.issuerSignedItems) {
                enc.addBytes(item);
            }
        }
    }

    return enc.finish();
}

Result<AccessDocument> decodeAccessDocument(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);

    AccessDocument doc;

    for (size_t i = 0; i < *count; ++i) {
        auto key = dec.getText();
        if (!key) return tl::unexpected(AliroError::DECODING_ERROR);

        if (*key == "docType") {
            auto v = dec.getText();
            if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
            doc.docType = std::move(*v);
        } else if (*key == "issuerAuth") {
            auto bytes = dec.getBytes();
            if (!bytes) return tl::unexpected(AliroError::DECODING_ERROR);
            auto auth = decodeIssuerAuth(*bytes);
            if (!auth) return tl::unexpected(auth.error());
            doc.issuerAuth = std::move(*auth);
        } else if (*key == "nameSpaces") {
            auto nsCount = dec.getMapSize();
            if (!nsCount) return tl::unexpected(AliroError::DECODING_ERROR);
            for (size_t j = 0; j < *nsCount; ++j) {
                NameSpaceItems ns;
                auto nsKey = dec.getText();
                if (!nsKey) return tl::unexpected(AliroError::DECODING_ERROR);
                ns.nameSpace = std::move(*nsKey);
                auto itemCount = dec.getArraySize();
                if (!itemCount) return tl::unexpected(AliroError::DECODING_ERROR);
                for (size_t k = 0; k < *itemCount; ++k) {
                    auto item = dec.getBytes();
                    if (!item) return tl::unexpected(AliroError::DECODING_ERROR);
                    ns.issuerSignedItems.push_back(std::move(*item));
                }
                doc.nameSpaces.push_back(std::move(ns));
            }
        } else {
            if (!dec.skip()) return tl::unexpected(AliroError::DECODING_ERROR);
        }
    }
    return doc;
}

} // namespace aliro
