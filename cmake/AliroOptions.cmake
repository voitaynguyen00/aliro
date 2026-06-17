option(ALIRO_BUILD_TESTS    "Build test targets"     ON)
option(ALIRO_BUILD_EXAMPLES "Build example targets"  OFF)

set(ALIRO_CRYPTO_BACKEND "openssl" CACHE STRING "Crypto backend: openssl or mbedtls")
set_property(CACHE ALIRO_CRYPTO_BACKEND PROPERTY STRINGS openssl mbedtls)
