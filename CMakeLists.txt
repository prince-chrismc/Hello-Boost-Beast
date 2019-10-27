cmake_minimum_required(VERSION 3.8)

project(Hello-Boost-Beast)

option(CMAKE_TOOLCHAIN_FILE "Path to vcpkg.cmake tool chain file")

include(${CMAKE_TOOLCHAIN_FILE})

# .\vcpkg install boost:x64-windows-static openssl:x64-windows-static
find_package(Boost 1.69 COMPONENTS system thread REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)

add_executable(restful
               src/main.cpp
               src/server_certificate.hpp
               src/set_cipher_list.hpp
               src/use_tmp_ecdh.hpp)

set_target_properties(restful
                      PROPERTIES CXX_STANDARD
                                 11
                                 CXX_STANDARD_REQUIRED
                                 YES
                                 CXX_EXTENSIONS
                                 OFF)

target_link_libraries(restful
                      PRIVATE Boost::system
                              Boost::thread
                              OpenSSL::SSL
                              OpenSSL::Crypto
                              fmt::fmt
                              fmt::fmt-header-only)
