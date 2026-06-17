add_executable(aliro-device-tests
    deviceSessionTest.cpp
)

target_link_libraries(aliro-device-tests
    PRIVATE
        aliro-device
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(aliro-device-tests)
