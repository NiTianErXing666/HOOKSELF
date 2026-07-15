cmake_minimum_required(VERSION 3.22.1)

project(hookself_demo LANGUAGES C CXX)

find_package(hookself REQUIRED CONFIG)

add_library(hookself_demo SHARED
        demo/demo_runtime.cpp
        jni/demo_jni.cpp)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_sources(hookself_demo PRIVATE jni/demo_test_jni.cpp)
    target_compile_definitions(
            hookself_demo PRIVATE HOOKSELF_DEMO_BUILD_TEST_SUPPORT=1)
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
        hookself::hookself)
