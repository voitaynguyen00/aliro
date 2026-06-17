cmake_minimum_required(VERSION 3.20)

project(Aliro
    VERSION 1.0.0
    DESCRIPTION "Aliro 1.0 protocol C++ implementation"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(AliroOptions)
include(AliroVersion)
include(FetchContent)

# tl::expected — Result<T,E> (std::expected backport)
FetchContent_Declare(
    tl_expected
    GIT_REPOSITORY https://github.com/TartanLlama/expected.git
    GIT_TAG        v1.1.0
    GIT_SHALLOW    TRUE
)
set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(tl_expected)

# GoogleTest
if(ALIRO_BUILD_TESTS)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
        GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
    include(GoogleTest)
endif()

add_subdirectory(modules/core)

if(ALIRO_BUILD_TESTS)
    add_subdirectory(tests)
endif()
