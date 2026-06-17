add_executable(aliro-crypto-tests
    ecdsaTest.cpp
    ecdhTest.cpp
    aesGcmTest.cpp
    hkdfTest.cpp
    randomTest.cpp
)

target_link_libraries(aliro-crypto-tests
    PRIVATE
        aliro-crypto
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(aliro-crypto-tests)
