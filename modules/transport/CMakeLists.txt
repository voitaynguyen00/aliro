add_library(aliro-transport STATIC
    src/simTransport.cpp
)

target_include_directories(aliro-transport
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(aliro-transport
    PUBLIC
        aliro-core
)

target_compile_options(aliro-transport PRIVATE
    -Wall -Wextra -Wpedantic -Werror
)

target_compile_features(aliro-transport PUBLIC cxx_std_20)
