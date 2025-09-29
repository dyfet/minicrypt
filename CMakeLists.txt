# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

cmake_minimum_required(VERSION 3.16.0)
Project(minicrypt VERSION 0.4.0 LANGUAGES C)
set(CMAKE_C_STANDARD 11)
set(C_STANDARD_REQUIRED 11)

file(
    GLOB LINT_SOURCES
    RELATIVE ${PROJECT_SOURCE_DIR}
    src/*.h src/*.c)

include(cmake/custom.cmake OPTIONAL)
include(cmake/project.cmake)
include(cmake/features.cmake)
include(cmake/clint.cmake)
include(cmake/deploy.cmake OPTIONAL)

file(GLOB optional .git[a-z]* *.json *.in *.yml .clang* cmake/*)
file(GLOB headers src/*.h)
file(GLOB sources src/*.c)
file(GLOB markdown *.md)

if(WIN32)
    set(EXTRA_LINK_LIBS "-ladvapi32")
endif()

configure_file(minicrypt.pc.in minicrypt.pc)
enable_testing()

option(BUILD_SHARED_LIBS "Build shared libraries" ON)
add_library(minicrypt ${sources} ${headers})
if(BUILD_SHARED_LIBS AND CMAKE_BUILD_TYPE MATCHES "^Rel")
    set_target_properties(minicrypt PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
endif()

if(WIN32)
    target_link_libraries(minicrypt PUBLIC advapi32)
endif()

add_executable(test_sha1 test/sha1.c src/sha1.h)
add_test(NAME test-sha1 COMMAND test_sha1)
target_link_libraries(test_sha1 PRIVATE minicrypt)

add_executable(test_sha256 test/sha256.c src/sha256.h)
add_test(NAME test-sha256 COMMAND test_sha256)
target_link_libraries(test_sha256 PRIVATE minicrypt)

add_executable(test_hmac test/hmac.c src/hmac.h)
add_test(NAME test-hmac COMMAND test_hmac)
target_link_libraries(test_hmac PRIVATE minicrypt)

add_executable(test_md5 test/md5.c src/md5.h)
add_test(NAME test-md5 COMMAND test_md5)
target_link_libraries(test_md5 PRIVATE minicrypt)

add_executable(test_random test/random.c src/random.h)
add_test(NAME test-random COMMAND test_random)
target_link_libraries(test_random PRIVATE minicrypt)

add_executable(test_crc test/crc.c src/crc.h)
add_test(NAME test-crc COMMAND test_crc)
target_link_libraries(test_crc PRIVATE minicrypt)

add_executable(test_ring256 test/ring256.c src/ring256.h)
add_test(NAME test-ring256 COMMAND test_ring256)
target_link_libraries(test_ring256 PRIVATE minicrypt)

add_executable(test_aes test/aes.c src/aes.h)
add_test(NAME test-aes COMMAND test_aes)
target_link_libraries(test_aes PRIVATE minicrypt)

# Extras...
add_custom_target(header-files SOURCES ${headers})
add_custom_target(support-files SOURCES ${markdown} ${optional})

install(FILES ${headers} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/minicrypt")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/minicrypt.pc DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig")

install(TARGETS minicrypt
    EXPORT minicryptTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/minicrypt
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/minicrypt
)

install(EXPORT minicryptTargets
    FILE minicryptTargets.cmake
    NAMESPACE minicrypt::
    DESTINATION lib/cmake/minicrypt
)

