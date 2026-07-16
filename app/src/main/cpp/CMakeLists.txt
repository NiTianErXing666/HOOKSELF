cmake_minimum_required(VERSION 3.22.1)

project(hookself_demo LANGUAGES C CXX ASM)

find_package(hookself REQUIRED CONFIG)

add_library(hookself_demo SHARED
        demo/demo_runtime.cpp
        jni/demo_jni.cpp)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_library(hookself_elf_fixture_gnu SHARED
            elf_test/fixture_gnu.c)
    target_link_options(hookself_elf_fixture_gnu PRIVATE
            -Wl,--hash-style=gnu
            -Wl,-z,relro
            -Wl,-z,now)

    add_library(hookself_elf_fixture_sysv SHARED
            elf_test/fixture_sysv.c)
    target_link_options(hookself_elf_fixture_sysv PRIVATE
            -Wl,--hash-style=sysv
            -Wl,-z,relro
            -Wl,-z,now)

    add_library(hookself_elf_fixture_consumer SHARED
            elf_test/fixture_consumer.c)
    target_compile_options(hookself_elf_fixture_consumer PRIVATE
            -fno-builtin)
    target_link_options(hookself_elf_fixture_consumer PRIVATE
            -Wl,--hash-style=both
            -Wl,-z,relro
            -Wl,-z,now)
    target_link_libraries(hookself_elf_fixture_consumer PRIVATE
            hookself_elf_fixture_gnu
            hookself_elf_fixture_sysv)

    add_library(hookself_elf_fixture_lifecycle SHARED
            elf_test/fixture_lifecycle.c)
    target_link_options(hookself_elf_fixture_lifecycle PRIVATE
            -Wl,-z,relro
            -Wl,-z,now)

    add_library(hookself_elf_fixture_unloadable SHARED
            elf_test/fixture_unloadable.c)
    target_compile_options(hookself_elf_fixture_unloadable PRIVATE
            -fno-builtin)
    target_link_options(hookself_elf_fixture_unloadable PRIVATE
            -Wl,--hash-style=both
            -Wl,-z,relro
            -Wl,-z,now)
    target_link_libraries(hookself_elf_fixture_unloadable PRIVATE
            hookself_elf_fixture_gnu)

    target_sources(hookself_demo PRIVATE
            jni/demo_test_jni.cpp
            jni/elf_test_jni.cpp
            jni/inline_test_jni.cpp
            inline_test/arm64_relocation_fixtures.S)
    target_compile_definitions(
            hookself_demo PRIVATE HOOKSELF_DEMO_BUILD_TEST_SUPPORT=1)
    target_link_libraries(hookself_demo PRIVATE
            hookself_elf_fixture_consumer)
    add_dependencies(hookself_demo
            hookself_elf_fixture_lifecycle
            hookself_elf_fixture_unloadable)
endif()

target_include_directories(hookself_demo PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/demo)
target_compile_features(hookself_demo PRIVATE cxx_std_17)
target_compile_definitions(hookself_demo PRIVATE _GNU_SOURCE)
target_compile_options(hookself_demo PRIVATE
        -Wall
        -Wextra
        -Werror=return-type
        -fvisibility=hidden
        -fvisibility-inlines-hidden)
target_link_options(hookself_demo PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/hookself_demo.exports.map"
        -Wl,--exclude-libs,ALL)
target_link_libraries(hookself_demo PRIVATE
        android
        log
        hookself::hookself
        hookself::hookself_elf
        hookself::hookself_inline)
