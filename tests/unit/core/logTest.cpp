#include <gtest/gtest.h>

#include <string>

#include "aliro/core/log.h"

using namespace aliro;

// Helper: install a capturing callback and restore nullptr on teardown.
struct LogCapture {
    log::Level lastLevel{log::Level::NONE};
    std::string lastMessage;
    int callCount{0};

    LogCapture() {
        instance = this;
        log::setCallback(
            [](log::Level lv, const char*, int, const char* msg) {
                instance->lastLevel = lv;
                instance->lastMessage = msg;
                ++instance->callCount;
            },
            log::Level::DEBUG);
    }
    ~LogCapture() {
        log::setCallback(nullptr);
        instance = nullptr;
    }
    static LogCapture* instance;
};
LogCapture* LogCapture::instance = nullptr;

TEST(LogTest, noCallback_doesNotCrash) {
    log::setCallback(nullptr);
    // None of these should crash or do anything.
    ALIRO_LOG_DEBUG("debug message");
    ALIRO_LOG_INFO("info message");
    ALIRO_LOG_WARN("warn message");
    ALIRO_LOG_ERROR("error message");
}

TEST(LogTest, callback_receivesCorrectLevelAndMessage) {
    LogCapture cap;
    ALIRO_LOG_INFO("hello %d", 42);
    EXPECT_EQ(cap.lastLevel, log::Level::INFO);
    EXPECT_EQ(cap.lastMessage, "hello 42");
    EXPECT_EQ(cap.callCount, 1);
}

TEST(LogTest, minLevel_filtersLowerSeverity) {
    LogCapture cap;
    log::setCallback(
        LogCapture::instance->lastLevel == log::Level::NONE ? nullptr : nullptr,  // reset first
        log::Level::WARN);
    // Re-install at WARN level
    log::setCallback(
        [](log::Level lv, const char*, int, const char* msg) {
            LogCapture::instance->lastLevel = lv;
            LogCapture::instance->lastMessage = msg;
            ++LogCapture::instance->callCount;
        },
        log::Level::WARN);

    cap.callCount = 0;
    ALIRO_LOG_DEBUG("should be filtered");
    ALIRO_LOG_INFO("also filtered");
    EXPECT_EQ(cap.callCount, 0);
}

TEST(LogTest, minLevel_passesEqualOrHigherSeverity) {
    LogCapture cap;
    log::setCallback(
        [](log::Level lv, const char*, int, const char* msg) {
            LogCapture::instance->lastLevel = lv;
            LogCapture::instance->lastMessage = msg;
            ++LogCapture::instance->callCount;
        },
        log::Level::WARN);

    ALIRO_LOG_WARN("warning fires");
    ALIRO_LOG_ERROR("error fires");
    EXPECT_EQ(cap.callCount, 2);
    EXPECT_EQ(cap.lastLevel, log::Level::ERROR);
}

TEST(LogTest, allFourLevelsDispatch) {
    LogCapture cap;
    ALIRO_LOG_DEBUG("d");
    ALIRO_LOG_INFO("i");
    ALIRO_LOG_WARN("w");
    ALIRO_LOG_ERROR("e");
    EXPECT_EQ(cap.callCount, 4);
}
