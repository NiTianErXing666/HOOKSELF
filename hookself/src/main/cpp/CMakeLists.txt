cmake_minimum_required(VERSION 3.22.1)

project(hookself LANGUAGES C CXX ASM)

option(HOOKSELF_BUILD_TEST_SUPPORT
       "Build instrumentation probes and native self-tests" OFF)

if(ANDROID AND NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "HookSelf currently supports arm64-v8a only")
endif()

set(HOOKSELF_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/hookself)
set(HOOKSELF_PUBLIC_INCLUDE ${HOOKSELF_ROOT}/include)

add_library(hookself_tracer_core STATIC
        ${HOOKSELF_ROOT}/platform/raw_syscall_arm64.cpp
        ${HOOKSELF_ROOT}/platform/runtime_bypass_gettid_arm64.S
        ${HOOKSELF_ROOT}/platform/procfs.cpp
        ${HOOKSELF_ROOT}/arch/arm64_regs.cpp
        ${HOOKSELF_ROOT}/tracer/close_range_replay.cpp
        ${HOOKSELF_ROOT}/tracer/logical_ptrace.cpp
        ${HOOKSELF_ROOT}/tracer/mount_syscall_state.cpp
        ${HOOKSELF_ROOT}/tracer/path_state.cpp
        ${HOOKSELF_ROOT}/tracer/remote_syscall_arm64.cpp
        ${HOOKSELF_ROOT}/tracer/task_table.cpp
        ${HOOKSELF_ROOT}/tracer/wait_decoder.cpp
        ${HOOKSELF_ROOT}/internal/logical_ptrace_dispatcher.cpp
        ${HOOKSELF_ROOT}/internal/logical_ptrace_resident_state.cpp
        ${HOOKSELF_ROOT}/internal/proc_status_view.cpp
        ${HOOKSELF_ROOT}/internal/proc_virtual_dispatch.cpp
        ${HOOKSELF_ROOT}/internal/proc_virtual_resident_state.cpp
        ${HOOKSELF_ROOT}/internal/proc_virtual_view.cpp
        ${HOOKSELF_ROOT}/internal/selective_seccomp_filter.cpp
        ${HOOKSELF_ROOT}/internal/selective_seccomp_plan.cpp
        ${HOOKSELF_ROOT}/internal/resident_session.cpp)

target_include_directories(hookself_tracer_core PRIVATE
        ${HOOKSELF_PUBLIC_INCLUDE}
        ${HOOKSELF_ROOT})
target_compile_features(hookself_tracer_core PRIVATE cxx_std_17)
target_compile_definitions(hookself_tracer_core PRIVATE _GNU_SOURCE)
target_compile_options(hookself_tracer_core PRIVATE
        -Wall
        -Wextra
        -Werror=return-type
        -fno-exceptions
        -fno-rtti
        -fvisibility=hidden
        -fvisibility-inlines-hidden)
set_target_properties(hookself_tracer_core PROPERTIES
        POSITION_INDEPENDENT_CODE ON)

add_library(hookself SHARED
        ${HOOKSELF_ROOT}/api/config_api.cpp
        ${HOOKSELF_ROOT}/framework.cpp
        ${HOOKSELF_ROOT}/internal/event_ring.cpp
        ${HOOKSELF_ROOT}/internal/shared_abi.cpp
        ${HOOKSELF_ROOT}/internal/virtual_file_store.cpp
        ${HOOKSELF_ROOT}/internal/virtual_file_provider.cpp
        ${HOOKSELF_ROOT}/runtime_api.cpp
        ${HOOKSELF_ROOT}/logging.cpp)

if(HOOKSELF_BUILD_TEST_SUPPORT)
    target_sources(hookself_tracer_core PRIVATE
            ${HOOKSELF_ROOT}/platform/raw_clone_thread_arm64.S)
    target_compile_definitions(
            hookself_tracer_core PRIVATE HOOKSELF_BUILD_TEST_SUPPORT=1)
    target_sources(hookself PRIVATE
            ${HOOKSELF_ROOT}/internal/framework_facade_lifetime_selftest.cpp
            ${HOOKSELF_ROOT}/internal/framework_facade_runtime_selftest.cpp
            ${HOOKSELF_ROOT}/internal/framework_facade_selftest.cpp
            ${HOOKSELF_ROOT}/internal/framework_selftest.cpp
            ${HOOKSELF_ROOT}/internal/logical_ptrace_dispatcher_selftest.cpp
            ${HOOKSELF_ROOT}/internal/logical_ptrace_resident_state_selftest.cpp
            ${HOOKSELF_ROOT}/internal/nested_ptrace_resident_selftest.cpp
            ${HOOKSELF_ROOT}/internal/proc_virtual_selftest.cpp
            ${HOOKSELF_ROOT}/internal/resident_selftest.cpp
            ${HOOKSELF_ROOT}/internal/selective_resident_selftest.cpp
            ${HOOKSELF_ROOT}/internal/selective_seccomp_probe.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/test_support/path_policy.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/test_support/self_trace_probe.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/test_support/native_test_jni.cpp)
    target_compile_definitions(hookself PRIVATE HOOKSELF_BUILD_TEST_SUPPORT=1)
endif()

target_include_directories(hookself
        PUBLIC ${HOOKSELF_PUBLIC_INCLUDE}
        PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${HOOKSELF_ROOT})
target_compile_features(hookself PRIVATE cxx_std_17)
target_compile_definitions(hookself PRIVATE _GNU_SOURCE HOOKSELF_BUILDING_LIBRARY=1)
target_compile_options(hookself PRIVATE
        -Wall
        -Wextra
        -Werror=return-type
        -fvisibility=hidden
        -fvisibility-inlines-hidden)
target_link_options(hookself PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/hookself.exports.map"
        -Wl,--exclude-libs,ALL)
target_link_libraries(hookself PRIVATE
        android
        log
        hookself_tracer_core)
