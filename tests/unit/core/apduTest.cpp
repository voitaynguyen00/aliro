#include <gtest/gtest.h>

#include "aliro/core/apdu.h"

using namespace aliro;

TEST(ApduBuildTest, headerOnly_noData) {
    auto cmd = apdu::buildCommand(0x00, 0xA4, 0x04, 0x00, {}, false);
    Bytes expected = {0x00, 0xA4, 0x04, 0x00};
    EXPECT_EQ(cmd, expected);
}

TEST(ApduBuildTest, headerWithLe_noData) {
    auto cmd = apdu::buildCommand(0x00, 0xA4, 0x04, 0x00);
    Bytes expected = {0x00, 0xA4, 0x04, 0x00, 0x00};
    EXPECT_EQ(cmd, expected);
}

TEST(ApduBuildTest, shortData_producesLcDataLe) {
    Bytes data = {0x01, 0x02, 0x03};
    auto cmd = apdu::buildCommand(0x00, 0x87, 0x00, 0x00, data);
    // CLA INS P1 P2 Lc D1 D2 D3 Le
    Bytes expected = {0x00, 0x87, 0x00, 0x00, 0x03, 0x01, 0x02, 0x03, 0x00};
    EXPECT_EQ(cmd, expected);
}

TEST(ApduBuildTest, shortData_noLe) {
    Bytes data = {0xAA, 0xBB};
    auto cmd = apdu::buildCommand(0x00, 0x86, 0x00, 0x00, data, false);
    Bytes expected = {0x00, 0x86, 0x00, 0x00, 0x02, 0xAA, 0xBB};
    EXPECT_EQ(cmd, expected);
}

TEST(ApduBuildTest, aliroAid_selectCommand) {
    Bytes aid = {0xA0, 0x00, 0x00, 0x09, 0x63, 0x4C, 0x69, 0x72, 0x6F};
    auto cmd = apdu::buildCommand(0x00, 0xA4, 0x04, 0x00, aid);
    EXPECT_EQ(cmd.size(), 4u + 1u + 9u + 1u);  // header + Lc + AID + Le
    EXPECT_EQ(cmd[4], 0x09u);                  // Lc = 9
    EXPECT_EQ(cmd.back(), 0x00u);              // Le
}

TEST(ApduParseTest, successResponse_returnData) {
    Bytes resp = {0x01, 0x02, 0x03, 0x90, 0x00};
    auto data = apdu::parseResponse(resp);
    ASSERT_TRUE(data.has_value());
    EXPECT_EQ(*data, (Bytes{0x01, 0x02, 0x03}));
}

TEST(ApduParseTest, statusWordOnly_returnsEmpty) {
    Bytes resp = {0x90, 0x00};
    auto data = apdu::parseResponse(resp);
    ASSERT_TRUE(data.has_value());
    EXPECT_TRUE(data->empty());
}

TEST(ApduParseTest, nonSuccessSW_returnsError) {
    Bytes resp = {0x6A, 0x82};  // File not found
    auto data = apdu::parseResponse(resp);
    ASSERT_FALSE(data.has_value());
    EXPECT_EQ(data.error(), AliroError::INVALID_MESSAGE);
}

TEST(ApduParseTest, tooShort_returnsDecodeError) {
    Bytes resp = {0x90};
    auto data = apdu::parseResponse(resp);
    ASSERT_FALSE(data.has_value());
    EXPECT_EQ(data.error(), AliroError::DECODING_ERROR);
}

TEST(ApduParseTest, emptyResponse_returnsDecodeError) {
    Bytes resp = {};
    auto data = apdu::parseResponse(resp);
    EXPECT_FALSE(data.has_value());
}

TEST(ApduStatusWordTest, extract9000) {
    Bytes resp = {0xAA, 0x90, 0x00};
    EXPECT_EQ(apdu::statusWord(resp), 0x9000u);
}

TEST(ApduStatusWordTest, extract6A82) {
    Bytes resp = {0x6A, 0x82};
    EXPECT_EQ(apdu::statusWord(resp), 0x6A82u);
}

TEST(ApduStatusWordTest, tooShort_returnsZero) {
    Bytes resp = {0x90};
    EXPECT_EQ(apdu::statusWord(resp), 0u);
}
