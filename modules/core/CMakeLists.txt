add_library(aliro-core STATIC
    src/apdu.cpp
    src/tlv.cpp
    src/cbor.cpp
    src/issuerAuth.cpp
    src/accessDocument.cpp
    src/revocationDocument.cpp
    src/log.cpp
)

target_include_directories(aliro-core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(aliro-core
    PUBLIC tl::expected
)

target_compile_options(aliro-core PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

target_compile_features(aliro-core PUBLIC cxx_std_20)
