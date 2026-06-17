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

find_package(OpenSSL 3.0 REQUIRED)

add_library(aliro-crypto STATIC
    src/openSslCryptoProvider.cpp
)

target_include_directories(aliro-crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(aliro-crypto
    PUBLIC
        aliro-core
        OpenSSL::Crypto
)

target_compile_options(aliro-crypto PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

target_compile_features(aliro-crypto PUBLIC cxx_std_20)
