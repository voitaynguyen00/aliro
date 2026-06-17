#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "aliro/core/issuerAuth.h"
#include "aliro/core/types.h"

namespace aliro {

enum class ChangeMode : uint8_t { OVERWRITE = 0, UPDATE = 1 };

struct RevocationEntry {
    Bytes credentialId;
};

/// RevocationDataElement: one revocation list update (spec §7.6).
struct RevocationDataElement {
    uint32_t version{1};
    ChangeMode changeMode{ChangeMode::OVERWRITE};
    std::vector<RevocationEntry> entries;
    std::vector<RevocationEntry> entriesRemove;  // only valid when changeMode == UPDATE
};

/// RevocationDocument: carries revocation data from issuer to Reader (spec §7.6).
struct RevocationDocument {
    std::string docType;
    IssuerAuth issuerAuth;
    std::vector<RevocationDataElement> revocationElements;
};

Result<Bytes> encodeRevocationDocument(const RevocationDocument& doc);
Result<RevocationDocument> decodeRevocationDocument(ByteView data);

}  // namespace aliro
