#pragma once

#include "aliro/core/types.h"
#include "aliro/core/issuerAuth.h"
#include <string>
#include <vector>

namespace aliro {

/// One namespace worth of signed items within an AccessDocument.
struct NameSpaceItems {
    std::string        nameSpace;
    std::vector<Bytes> issuerSignedItems; // each element is an encoded IssuerSignedItem
};

/// AccessDocument: ISO 18013-5 based structure carrying Aliro access data (spec §7.2).
struct AccessDocument {
    std::string                  docType;
    IssuerAuth                   issuerAuth;
    std::vector<NameSpaceItems>  nameSpaces;
};

Result<Bytes>          encodeAccessDocument(const AccessDocument& doc);
Result<AccessDocument> decodeAccessDocument(ByteView data);

} // namespace aliro
