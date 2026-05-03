cmake_minimum_required(VERSION 3.27)
project(revdump_ida_plugin LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

set(FETCHCONTENT_UPDATES_DISCONNECTED ON CACHE BOOL
    "Do not re-check FetchContent remotes on every build" FORCE)

FetchContent_Declare(
    idax
    GIT_REPOSITORY https://github.com/19h/idax.git
    GIT_TAG        master
)

if(DEFINED ENV{IDASDK} AND NOT "$ENV{IDASDK}" STREQUAL "")
    set(_revdump_idasdk "$ENV{IDASDK}")
    if(NOT EXISTS "${_revdump_idasdk}/ida-cmake/bootstrap.cmake" AND
       NOT EXISTS "${_revdump_idasdk}/cmake/bootstrap.cmake" AND
       NOT EXISTS "${_revdump_idasdk}/src/ida-cmake/bootstrap.cmake" AND
       NOT EXISTS "${_revdump_idasdk}/src/cmake/bootstrap.cmake")
        message(WARNING "Ignoring invalid IDASDK='${_revdump_idasdk}' so idax can fetch ida-sdk")
        set(ENV{IDASDK} "")
    endif()
endif()

FetchContent_MakeAvailable(idax)

function(revdump_strip_lto target_name)
    foreach(prop COMPILE_OPTIONS LINK_OPTIONS INTERFACE_COMPILE_OPTIONS INTERFACE_LINK_OPTIONS)
        get_target_property(_opts "${target_name}" "${prop}")
        if(_opts AND NOT _opts STREQUAL "_opts-NOTFOUND")
            list(FILTER _opts EXCLUDE REGEX "^-flto($|=.*)")
            set_property(TARGET "${target_name}" PROPERTY "${prop}" "${_opts}")
        endif()
    endforeach()
endfunction()

foreach(_target ida_compiler_settings ida_platform_settings idasdk_headers)
    if(TARGET "${_target}")
        revdump_strip_lto("${_target}")
    endif()
endforeach()

ida_add_plugin(revdump_ida_plugin
    SOURCES revdump_ida_plugin.cpp
    LIBRARIES idax::idax
)

target_compile_features(revdump_ida_plugin PRIVATE cxx_std_23)
set_property(TARGET revdump_ida_plugin PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)

if(MSVC)
    target_compile_options(revdump_ida_plugin PRIVATE /W4 /permissive- /Zc:__cplusplus)
else()
    target_compile_options(revdump_ida_plugin PRIVATE -Wall -Wextra -Wpedantic -fno-lto)
    target_link_options(revdump_ida_plugin PRIVATE -fno-lto)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        find_program(REVDUMP_LLD_LINKER ld.lld lld)
        if(REVDUMP_LLD_LINKER)
            target_link_options(revdump_ida_plugin PRIVATE -fuse-ld=lld)
        endif()
    endif()
endif()

revdump_strip_lto(revdump_ida_plugin)
