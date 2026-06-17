#pragma once

#include <cstdint>
#include <string_view>

namespace aliro::protocol {

// Aliro docType (ISO 18013-5 namespace)
constexpr std::string_view kAliroDocType      = "0.0.1.0.0.0.0.1";
constexpr std::string_view kAliroNameSpace    = "0.0.1.0.0.0.0.1";
constexpr std::string_view kRevocationDocType = "0.0.1.0.0.0.0.2";

// APDU command class byte
constexpr uint8_t kAliroCla = 0x00;

// APDU instruction bytes (ISO 7816-4)
constexpr uint8_t kInsSelect      = 0xA4;
constexpr uint8_t kInsAuth0       = 0x87;
constexpr uint8_t kInsAuth1       = 0x86;
constexpr uint8_t kInsEnvelope    = 0xC3;
constexpr uint8_t kInsGetData     = 0xCB;

// AID for Aliro application selection
constexpr uint8_t kAliroAid[] = {0xA0, 0x00, 0x00, 0x09, 0x63, 0x4C, 0x69, 0x72, 0x6F};

// DER-TLV tags used in Aliro APDU data fields (per spec section 8.3)
constexpr uint32_t kTagCryptogram          = 0x9D;
constexpr uint32_t kTagEphemeralPublicKey  = 0x86;
constexpr uint32_t kTagSignature           = 0x9E;
constexpr uint32_t kTagReaderIdentifier    = 0x83;
constexpr uint32_t kTagReaderNonce         = 0x85;
constexpr uint32_t kTagDeviceNonce         = 0x8A;
constexpr uint32_t kTagReaderCert          = 0x67;
constexpr uint32_t kTagDeviceRequest       = 0xA7;
constexpr uint32_t kTagDeviceResponse      = 0xA8;

// IssuerAuth key remapping (spec Table 7-1)
constexpr std::string_view kIssuerAuthVersion       = "1";
constexpr std::string_view kIssuerAuthDigestAlg     = "2";
constexpr std::string_view kIssuerAuthValueDigests  = "3";
constexpr std::string_view kIssuerAuthDeviceKeyInfo = "4";
constexpr std::string_view kIssuerAuthDocType       = "5";
constexpr std::string_view kIssuerAuthValidityInfo  = "6";

// IssuerSignedItem key remapping (spec Table 7-2)
constexpr std::string_view kSignedItemDigestId      = "1";
constexpr std::string_view kSignedItemRandom        = "2";
constexpr std::string_view kSignedItemElementId     = "3";
constexpr std::string_view kSignedItemElementValue  = "4";

// AccessData key values (spec section 7.3)
constexpr uint64_t kAccessDataVersion    = 0;
constexpr uint64_t kAccessDataId         = 1;
constexpr uint64_t kAccessDataRules      = 2;
constexpr uint64_t kAccessDataSchedules  = 3;
constexpr uint64_t kAccessDataReaderIds  = 4;
constexpr uint64_t kAccessDataNonAccExt  = 5;
constexpr uint64_t kAccessDataAccExt     = 6;

// AccessRule key values (spec section 7.3.3)
constexpr uint64_t kAccessRuleCapabilities      = 0;
constexpr uint64_t kAccessRuleAllowScheduleIds  = 1;
constexpr uint64_t kAccessRuleDenyScheduleIds   = 2;
constexpr uint64_t kAccessRuleReaderRuleIds      = 3;

// AccessRuleCapabilities bit positions
constexpr uint16_t kCapSecure                    = 1 << 0;
constexpr uint16_t kCapUnsecure                  = 1 << 1;
constexpr uint16_t kCapToggleSecureOrUnsecure    = 1 << 2;
constexpr uint16_t kCapMomentaryUnsecure         = 1 << 3;
constexpr uint16_t kCapExtendedMomentaryUnsecure = 1 << 4;
constexpr uint16_t kCapPaymentPermission         = 1 << 5;

// Schedule key values (spec section 7.3.4)
constexpr uint64_t kScheduleStartPeriod    = 0;
constexpr uint64_t kScheduleEndPeriod      = 1;
constexpr uint64_t kScheduleRecurrenceRule = 2;
constexpr uint64_t kScheduleFlags          = 3;

// Cryptographic constants
constexpr size_t kEcPublicKeySize  = 65;  // uncompressed P-256 point
constexpr size_t kEcPrivateKeySize = 32;
constexpr size_t kSignatureSize    = 64;  // raw r||s
constexpr size_t kAesKeySize       = 16;  // AES-128
constexpr size_t kGcmNonceSize     = 12;
constexpr size_t kGcmTagSize       = 16;
constexpr size_t kKpersistentSize  = 32;

} // namespace aliro::protocol
