add_executable(aliro-integration-tests
    sessionFlowTest.cpp
)

target_link_libraries(aliro-integration-tests
    PRIVATE
        aliro-reader
        aliro-device
        GTest::gtest_main
)

gtest_discover_tests(aliro-integration-tests)
