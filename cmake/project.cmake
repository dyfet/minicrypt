# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 David Sugar <tychosoft@gmail.com>

macro(install_exec target new_name)
    set(_install_dir "${CMAKE_INSTALL_BINDIR}")
    if(${ARGC} GREATER 2)
        set(_install_dir "${ARGV2}")
    endif()

    if(NOT TARGET ${target})
        message(FATAL_ERROR "Target '${target}' not found")
    endif()

    if(WIN32)
        install(
            FILES "$<TARGET_FILE:${target}>"
            DESTINATION "${_install_dir}"
            RENAME "${new_name}"
        )
    else()
        install(
            FILES "$<TARGET_FILE:${target}>"
            DESTINATION "${_install_dir}"
            RENAME "${new_name}"
            PERMISSIONS
                OWNER_EXECUTE OWNER_WRITE OWNER_READ
                GROUP_EXECUTE GROUP_READ
                WORLD_EXECUTE WORLD_READ
        )
    endif()
endmacro()

string(TOLOWER "${PROJECT_NAME}" PROJECT_ARCHIVE)
include(GNUInstallDirs)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(BUILD_TESTING TRUE)
    if(NOT MSVC)
        list(APPEND CMAKE_CXX_FLAGS "-Wall")
    endif()
endif()

if(RELEASE AND NOT PROJECT_RELEASE)
    set(PROJECT_RELEASE "${RELEASE}")
elseif(NOT PROJECT_RELEASE)
    set(PROJECT_RELEASE "1")
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(EXISTS "/usr/local/lib/")
        include_directories("/usr/local/include")
        link_directories("/usr/local/lib")
    endif()
    if(EXISTS "/usr/pkg/lib/")
        include_directories("/usr/pkg/include")
        link_directories("/usr/pkg/lib")
    endif()
endif()

# Common tarball distribution
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git/")
    add_custom_target(dist
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        COMMAND "${CMAKE_COMMAND}" -E remove -F "${PROJECT_ARCHIVE}-*.tar.gz"
        COMMAND git archive -o "${PROJECT_ARCHIVE}-${PROJECT_VERSION}.tar.gz" --format tar.gz --prefix="${PROJECT_ARCHIVE}-${PROJECT_VERSION}/" "v${PROJECT_VERSION}" 2>/dev/null || git archive -o "${PROJECT_ARCHIVE}-${PROJECT_VERSION}.tar.gz" --format tar.gz --prefix="${PROJECT_ARCHIVE}-${PROJECT_VERSION}/" HEAD
    )
endif()
