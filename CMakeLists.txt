cmake_minimum_required(VERSION 3.11)

project(Hello-Boost-Beast)

option(CMAKE_TOOLCHAIN_FILE "Path to vcpkg.cmake tool chain file")

include(${CMAKE_TOOLCHAIN_FILE})

# .\vcpkg install boost:x64-windows-static openssl:x64-windows-static
find_package(Boost 1.67 COMPONENTS system thread REQUIRED)
find_package(OpenSSL REQUIRED)

add_executable(restful src/main.cpp)

target_link_libraries(restful PRIVATE Boost::system Boost::thread OpenSSL::SSL OpenSSL::Crypto)