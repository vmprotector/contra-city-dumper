cmake_minimum_required(VERSION 3.20)

project(ContraCityDumper VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CONTRA_DUMPER_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

add_executable(ContraCityDumper
    src/main.cpp
    src/common.cpp
    src/process.cpp
    src/pe.cpp
    src/metadata.cpp
    src/model.cpp
    src/layout.cpp
    src/loader.cpp
    src/json.cpp
    src/emit_json.cpp
    src/emit_hpp.cpp
)

target_include_directories(ContraCityDumper PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(ContraCityDumper PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(ContraCityDumper PRIVATE
        /W4
        /permissive-
        /utf-8
        /EHsc
        /Zc:__cplusplus
    )
    if(CONTRA_DUMPER_WARNINGS_AS_ERRORS)
        target_compile_options(ContraCityDumper PRIVATE /WX)
    endif()
else()
    target_compile_options(ContraCityDumper PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()

set_target_properties(ContraCityDumper PROPERTIES
    OUTPUT_NAME "ContraCityDumper"
    VS_DEBUGGER_WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
)

# Toolhelp32 and the process APIs are in kernel32; no third-party dependencies.
target_link_libraries(ContraCityDumper PRIVATE kernel32)

if(MSVC)
    set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}" PROPERTY
        VS_STARTUP_PROJECT ContraCityDumper)
endif()

install(TARGETS ContraCityDumper RUNTIME DESTINATION bin)
