cmake_minimum_required(VERSION 3.16)
project(rdp_nla_checker C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O3 -march=native -DNDEBUG")

# Default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Options
option(USE_DPDK "Enable DPDK support" OFF)
option(USE_HARDWARE_CRYPTO "Enable hardware crypto acceleration" OFF)
option(BUILD_TESTS "Build unit tests" OFF)
option(BUILD_BENCHMARKS "Build benchmark tools" OFF)

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(GSSAPI REQUIRED krb5-gssapi)
find_package(Threads REQUIRED)

# DPDK (optional)
if(USE_DPDK)
    pkg_check_modules(DPDK REQUIRED libdpdk)
    include_directories(${DPDK_INCLUDE_DIRS})
endif()

# Include directories
include_directories(src)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${GSSAPI_INCLUDE_DIRS})

# Check for gssapi/gssapi_ntlm.h
include(CheckIncludeFile)
check_include_file(gssapi/gssapi_ntlm.h HAVE_GSSAPI_NTLM_H)
if(HAVE_GSSAPI_NTLM_H)
    add_definitions(-DHAVE_GSSAPI_NTLM_H)
endif()

# Source files
set(SOURCES
    src/rdp_nla_checker.c
    src/credsp.c
    src/buffer_pool.c
    src/file_parser.c
    src/dpdk_impl.c
)

# Create executable
add_executable(rdp_nla_checker ${SOURCES})

# Link libraries
target_link_libraries(rdp_nla_checker
    ${OPENSSL_LIBRARIES}
    ${GSSAPI_LIBRARIES}
    Threads::Threads
)

if(USE_DPDK)
    target_link_libraries(rdp_nla_checker ${DPDK_LIBRARIES})
endif()

# Compiler-specific options
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(rdp_nla_checker PRIVATE -fno-strict-aliasing)
elseif(CMAKE_C_COMPILER_ID STREQUAL "Clang")
    target_compile_options(rdp_nla_checker PRIVATE -Wno-unused-parameter)
endif()

# Installation
install(TARGETS rdp_nla_checker
    RUNTIME DESTINATION bin
)

# Configuration files
install(FILES configs/rdp-checker.conf.example
    DESTINATION etc/rdp-checker
    RENAME rdp-checker.conf
)

install(FILES configs/targets.txt.example
    DESTINATION etc/rdp-checker
    RENAME targets.txt
)

install(FILES configs/credentials.txt.example
    DESTINATION etc/rdp-checker
    RENAME credentials.txt
)

# Documentation
install(FILES README.md LICENSE
    DESTINATION share/doc/rdp-nla-checker
)

# Systemd service (optional)
if(EXISTS /etc/systemd/system)
    install(FILES scripts/rdp-checker.service
        DESTINATION /etc/systemd/system
    )
endif()

# Tests
if(BUILD_TESTS)
    enable_testing()
    
    # Unit test executable
    add_executable(test_rdp_checker
        tests/test_main.c
        tests/test_credsp.c
        tests/test_asn1.c
        src/credsp.c
    )
    
    target_link_libraries(test_rdp_checker
        ${OPENSSL_LIBRARIES}
        ${GSSAPI_LIBRARIES}
        Threads::Threads
    )
    
    add_test(NAME unit_tests COMMAND test_rdp_checker)
endif()

# Benchmarks
if(BUILD_BENCHMARKS)
    add_executable(bench_tls_handshake
        benchmarks/bench_tls.c
        src/credsp.c
    )
    
    target_link_libraries(bench_tls_handshake
        ${OPENSSL_LIBRARIES}
        Threads::Threads
    )
endif()

# Package configuration
set(CPACK_PACKAGE_NAME "rdp-nla-checker")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_VENDOR "RDP Security Tools")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "High-performance RDP NLA credentials checker")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")

# DEB package
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3, libgssapi-krb5-2")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "RDP Security Tools <contact@example.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")

# RPM package
set(CPACK_RPM_PACKAGE_REQUIRES "openssl-libs, krb5-libs")
set(CPACK_RPM_PACKAGE_GROUP "Applications/Internet")

include(CPack)

# Custom targets
add_custom_target(format
    COMMAND clang-format -i src/*.c src/*.h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Formatting source code"
)

add_custom_target(analyze
    COMMAND cppcheck --enable=all --std=c99 src/
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Running static analysis"
)

# Print build configuration
message(STATUS "")
message(STATUS "RDP NLA Checker Build Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C compiler: ${CMAKE_C_COMPILER}")
message(STATUS "  C flags: ${CMAKE_C_FLAGS}")
message(STATUS "  DPDK support: ${USE_DPDK}")
message(STATUS "  Hardware crypto: ${USE_HARDWARE_CRYPTO}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build benchmarks: ${BUILD_BENCHMARKS}")
message(STATUS "")
