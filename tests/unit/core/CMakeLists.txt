add_executable(aliro-core-tests
    apduTest.cpp
    tlvTest.cpp
    cborTest.cpp
    issuerAuthTest.cpp
    accessDocumentTest.cpp
    revocationDocumentTest.cpp
    logTest.cpp
)

target_link_libraries(aliro-core-tests
    PRIVATE
        aliro-core
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(aliro-core-tests)
