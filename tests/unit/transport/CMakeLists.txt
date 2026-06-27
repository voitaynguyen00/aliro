add_executable(aliro-transport-tests
    simTransportTest.cpp
)

if(ALIRO_PCSC)
    target_sources(aliro-transport-tests PRIVATE pcscTransportTest.cpp)
endif()

target_link_libraries(aliro-transport-tests
    PRIVATE
        aliro-transport
        GTest::gtest_main
)

gtest_discover_tests(aliro-transport-tests)
