#pragma once

#include <optional>
#include <string>
#include <vector>

#include "aliro/core/accessRule.h"
#include "aliro/core/types.h"

namespace aliro {

struct VendorExtension {
    uint32_t vendorId;  // IEEE OUI or CID
    Bytes data;
};

struct AccessExtension {
    bool critical{false};
    VendorExtension extension;
};

/// AccessDataElement: signed data element within an Access Document (spec §7.3).
struct AccessDataElement {
    uint32_t version{1};
    std::optional<Bytes> id;
    std::optional<std::vector<AccessRule>> accessRules;
    std::optional<std::vector<Schedule>> schedules;
    std::optional<std::vector<uint32_t>> readerRuleIds;
    std::optional<std::vector<VendorExtension>> nonAccessExtensions;
    std::optional<std::vector<AccessExtension>> accessExtensions;
};

}  // namespace aliro
