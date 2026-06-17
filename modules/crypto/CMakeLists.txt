add_library(aliro-crypto STATIC
    src/openSslCryptoProvider.cpp
    src/mbedTlsCryptoProvider.cpp
    src/secureChannel.cpp
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
        mbedcrypto
)

target_compile_options(aliro-crypto PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

target_compile_features(aliro-crypto PUBLIC cxx_std_20)
