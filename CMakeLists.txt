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

# ---------------------------------------------------------------------------
# OpenSSL — prefers system install (Homebrew on macOS, libssl-dev on Linux).
# Falls back to the bundled submodule at third_party/openssl if unavailable.
# ---------------------------------------------------------------------------
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
    find_program(BREW brew)
    if(BREW)
        execute_process(
            COMMAND ${BREW} --prefix openssl@3
            OUTPUT_VARIABLE BREW_OPENSSL_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
        )
        if(BREW_OPENSSL_DIR AND EXISTS "${BREW_OPENSSL_DIR}")
            set(OPENSSL_ROOT_DIR "${BREW_OPENSSL_DIR}")
        endif()
    endif()
endif()

find_package(OpenSSL 3.0 QUIET)

if(NOT OPENSSL_FOUND)
    message(STATUS "System OpenSSL not found — building from submodule third_party/openssl")
    # openssl/openssl CMake support (3.2+) invokes Perl's Configure script.
    # Perl must be available on the build host.
    set(OPENSSL_NO_TESTS ON CACHE BOOL "" FORCE)
    add_subdirectory(third_party/openssl EXCLUDE_FROM_ALL)
    if(NOT TARGET OpenSSL::Crypto)
        add_library(OpenSSL::Crypto ALIAS crypto)
    endif()
    if(NOT TARGET OpenSSL::SSL)
        add_library(OpenSSL::SSL ALIAS ssl)
    endif()
endif()

# ---------------------------------------------------------------------------
# MbedTLS — always built from the bundled submodule at third_party/mbedtls.
# ---------------------------------------------------------------------------
set(ENABLE_TESTING         OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS        OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/mbedtls)

# ---------------------------------------------------------------------------
# tl::expected — Result<T,E> (std::expected backport)
# ---------------------------------------------------------------------------
FetchContent_Declare(
    tl_expected
    GIT_REPOSITORY https://github.com/TartanLlama/expected.git
    GIT_TAG        master
    GIT_SHALLOW    TRUE
)
set(EXPECTED_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(tl_expected)

# ---------------------------------------------------------------------------
# GoogleTest
# ---------------------------------------------------------------------------
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
add_subdirectory(modules/crypto)
add_subdirectory(modules/transport)
add_subdirectory(modules/reader)
add_subdirectory(modules/device)

if(ALIRO_BUILD_TESTS)
    add_subdirectory(tests)
endif()

if(ALIRO_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()
