#include "aliro/core/revocationDocument.h"
#include "aliro/core/cbor.h"

namespace aliro {

namespace {

Result<Bytes> encodeRevocationDataElement(const RevocationDataElement& elem) {
    cbor::Encoder enc;
    size_t fieldCount = 2
        + (elem.entries.empty() ? 0 : 1)
        + (elem.entriesRemove.empty() ? 0 : 1);
    enc.beginMap(fieldCount);

    enc.addUint(0); enc.addUint(elem.version);
    enc.addUint(2); enc.addUint(static_cast<uint64_t>(elem.changeMode));

    if (!elem.entries.empty()) {
        enc.addUint(3);
        enc.beginArray(elem.entries.size());
        for (const auto& e : elem.entries) enc.addBytes(e.credentialId);
    }
    if (!elem.entriesRemove.empty()) {
        enc.addUint(4);
        enc.beginArray(elem.entriesRemove.size());
        for (const auto& e : elem.entriesRemove) enc.addBytes(e.credentialId);
    }
    return enc.finish();
}

Result<RevocationDataElement> decodeRevocationDataElement(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);

    RevocationDataElement elem;
    for (size_t i = 0; i < *count; ++i) {
        auto key = dec.getUint();
        if (!key) return tl::unexpected(AliroError::DECODING_ERROR);
        switch (*key) {
            case 0: {
                auto v = dec.getUint();
                if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
                elem.version = static_cast<uint32_t>(*v);
                break;
            }
            case 2: {
                auto v = dec.getUint();
                if (!v) return tl::unexpected(AliroError::DECODING_ERROR);
                elem.changeMode = static_cast<ChangeMode>(*v);
                break;
            }
            case 3: {
                auto n = dec.getArraySize();
                if (!n) return tl::unexpected(AliroError::DECODING_ERROR);
                for (size_t j = 0; j < *n; ++j) {
                    auto b = dec.getBytes();
                    if (!b) return tl::unexpected(AliroError::DECODING_ERROR);
                    elem.entries.push_back({std::move(*b)});
                }
                break;
            }
            case 4: {
                auto n = dec.getArraySize();
                if (!n) return tl::unexpected(AliroError::DECODING_ERROR);
                for (size_t j = 0; j < *n; ++j) {
                    auto b = dec.getBytes();
                    if (!b) return tl::unexpected(AliroError::DECODING_ERROR);
                    elem.entriesRemove.push_back({std::move(*b)});
                }
                break;
            }
            default: {
                if (!dec.skip()) return tl::unexpected(AliroError::DECODING_ERROR);
                break;
            }
        }
    }
    return elem;
}

} // namespace

Result<Bytes> encodeRevocationDocument(const RevocationDocument& doc) {
    auto issuerAuthBytes = encodeIssuerAuth(doc.issuerAuth);
    if (!issuerAuthBytes) return tl::unexpected(issuerAuthBytes.error());

    cbor::Encoder enc;
    enc.beginMap(3);
    enc.addText("docType");    enc.addText(doc.docType);
    enc.addText("issuerAuth"); enc.addBytes(*issuerAuthBytes);
    enc.addText("revocationElements");
    enc.beginArray(doc.revocationElements.size());
    for (const auto& elem : doc.revocationElements) {
        auto elemBytes = encodeRevocationDataElement(elem);
        if (!elemBytes) return tl::unexpected(elemBytes.error());
        enc.addBytes(*elemBytes);
    }
    return enc.finish();
}

Result<RevocationDocument> decodeRevocationDocument(ByteView data) {
    cbor::Decoder dec(data);
    auto count = dec.getMapSize();
    if (!count) return tl::unexpected(AliroError::DECODING_ERROR);

    RevocationDocument doc;
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
        } else if (*key == "revocationElements") {
            auto n = dec.getArraySize();
            if (!n) return tl::unexpected(AliroError::DECODING_ERROR);
            for (size_t j = 0; j < *n; ++j) {
                auto elemBytes = dec.getBytes();
                if (!elemBytes) return tl::unexpected(AliroError::DECODING_ERROR);
                auto elem = decodeRevocationDataElement(*elemBytes);
                if (!elem) return tl::unexpected(elem.error());
                doc.revocationElements.push_back(std::move(*elem));
            }
        } else {
            if (!dec.skip()) return tl::unexpected(AliroError::DECODING_ERROR);
        }
    }
    return doc;
}

} // namespace aliro
