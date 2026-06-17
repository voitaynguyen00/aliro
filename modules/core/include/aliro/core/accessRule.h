#pragma once

#include "aliro/core/types.h"
#include <cstdint>
#include <optional>
#include <vector>

namespace aliro {

/// AccessRuleCapabilities bitmask (spec §7.3.3, Table 7-3).
struct AccessRuleCapabilities {
    bool secure{false};
    bool unsecure{false};
    bool toggleSecureOrUnsecure{false};
    bool momentaryUnsecure{false};
    bool extendedMomentaryUnsecure{false};
    bool paymentPermission{false};

    uint16_t toBits() const {
        uint16_t bits = 0;
        if (secure)                    bits |= (1 << 0);
        if (unsecure)                  bits |= (1 << 1);
        if (toggleSecureOrUnsecure)    bits |= (1 << 2);
        if (momentaryUnsecure)         bits |= (1 << 3);
        if (extendedMomentaryUnsecure) bits |= (1 << 4);
        if (paymentPermission)         bits |= (1 << 5);
        return bits;
    }

    static AccessRuleCapabilities fromBits(uint16_t bits) {
        AccessRuleCapabilities c;
        c.secure                    = (bits >> 0) & 1;
        c.unsecure                  = (bits >> 1) & 1;
        c.toggleSecureOrUnsecure    = (bits >> 2) & 1;
        c.momentaryUnsecure         = (bits >> 3) & 1;
        c.extendedMomentaryUnsecure = (bits >> 4) & 1;
        c.paymentPermission         = (bits >> 5) & 1;
        return c;
    }
};

/// AccessRule: one rule for a credential (spec §7.3.3).
struct AccessRule {
    std::optional<AccessRuleCapabilities> capabilities;
    std::optional<std::vector<uint32_t>>  allowScheduleIds;
    std::optional<std::vector<uint32_t>>  denyScheduleIds;
    std::optional<std::vector<uint32_t>>  readerRuleIds;
};

/// Schedule recurrence pattern (spec §7.3.4).
enum class RecurrencePattern : uint8_t {
    DAILY              = 0,
    WEEKLY             = 1,
    MONTHLY_BY_WEEKDAY = 2,
    MONTHLY_BY_DATE    = 3,
    YEARLY_BY_WEEKDAY  = 4,
    YEARLY_BY_DATE     = 5,
    YEARLY_BY_WEEK     = 6,
    YEARLY_BY_MONTH_WEEK = 7,
    YEARLY_BY_MONTH    = 8,
};

struct RecurrenceRule {
    RecurrencePattern pattern;
    uint32_t          interval{1};
    uint32_t          mask{0};
    int32_t           ordinal{0};
};

/// Schedule: time window for an access rule (spec §7.3.4).
struct Schedule {
    uint64_t                         startPeriod;  // Unix epoch seconds
    std::optional<uint64_t>          endPeriod;
    std::optional<RecurrenceRule>    recurrenceRule;
    uint32_t                         flags{0};
};

} // namespace aliro
