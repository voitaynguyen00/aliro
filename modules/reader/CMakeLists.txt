add_library(aliro-reader STATIC
    src/readerSession.cpp
)

target_include_directories(aliro-reader
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(aliro-reader
    PUBLIC
        aliro-core
        aliro-crypto
        aliro-transport
)

target_compile_options(aliro-reader PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

target_compile_features(aliro-reader PUBLIC cxx_std_20)
