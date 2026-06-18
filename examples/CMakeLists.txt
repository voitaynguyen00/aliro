add_executable(reader_demo reader_demo.cpp)
target_link_libraries(reader_demo PRIVATE
    aliro-reader
    aliro-device
    aliro-transport
    aliro-crypto
)

add_executable(device_demo device_demo.cpp)
target_link_libraries(device_demo PRIVATE
    aliro-reader
    aliro-device
    aliro-transport
    aliro-crypto
)
