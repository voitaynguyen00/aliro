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

if(ALIRO_PCSC)
    find_package(PCSC REQUIRED)
    target_sources(aliro-transport PRIVATE src/pcscTransport.cpp)
    target_link_libraries(aliro-transport PUBLIC PCSC::PCSC)
    target_compile_definitions(aliro-transport PUBLIC ALIRO_PCSC)
endif()
