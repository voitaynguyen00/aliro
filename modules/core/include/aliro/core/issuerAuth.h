#pragma once

#include "aliro/core/types.h"
#include "aliro/core/cbor.h"
#include <string>
#include <vector>

namespace aliro {

/// IssuerSignedItem: one signed namespace data element (spec §7.2, Table 7-2).
struct IssuerSignedItem {
    uint32_t    digestId;
    Bytes       random;             // 16-byte salt
    std::string elementIdentifier;
    Bytes       elementValue;       // CBOR-encoded element value
};

/// IssuerAuth: COSE_Sign1 structure carrying the signed Access Document (spec §7.2).
struct IssuerAuth {
    Bytes protectedHeader;    // serialized CBOR map (contains "alg")
    Bytes unprotectedHeader;  // serialized CBOR map (may be empty: A0)
    Bytes payload;            // IssuerNameSpaces CBOR bytes
    Bytes signature;          // 64-byte raw ECDSA P-256 signature (r||s)
};

Result<Bytes>            encodeIssuerSignedItem(const IssuerSignedItem& item);
Result<IssuerSignedItem> decodeIssuerSignedItem(ByteView data);

Result<Bytes>      encodeIssuerAuth(const IssuerAuth& auth);
Result<IssuerAuth> decodeIssuerAuth(ByteView data);

} // namespace aliro
