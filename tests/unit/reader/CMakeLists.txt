add_executable(aliro-reader-tests
    readerSessionTest.cpp
)

target_link_libraries(aliro-reader-tests
    PRIVATE
        aliro-reader
        aliro-device
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(aliro-reader-tests)
