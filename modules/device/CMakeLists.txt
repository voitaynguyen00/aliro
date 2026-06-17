add_library(aliro-device STATIC
    src/deviceSession.cpp
)

target_include_directories(aliro-device
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(aliro-device
    PUBLIC
        aliro-core
        aliro-crypto
        aliro-transport
)

target_compile_options(aliro-device PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

target_compile_features(aliro-device PUBLIC cxx_std_20)
