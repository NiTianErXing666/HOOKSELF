#include "framework_facade_runtime_selftest.h"

#include <asm/unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "hookself/framework.h"
#include "runtime_api_selftest.h"

namespace hookself::internal {
namespace {

struct ReentrantDestroyCapture {
    HookselfFramework* framework;
    uint32_t callbacks;
    uint32_t callbacks_after_destroy;
};

void DestroyFromSink(int32_t, const HookselfEvent*, const char*,
                     void* user_data) {
    auto* capture = static_cast<ReentrantDestroyCapture*>(user_data);
    ++capture->callbacks;
    if (capture->framework == nullptr) {
        ++capture->callbacks_after_destroy;
        return;
    }
    HookselfFramework* const framework = capture->framework;
    capture->framework = nullptr;
    hookself_framework_destroy(framework);
}

bool CopyString(char* destination, size_t capacity, const char* source) {
    if (destination == nullptr || capacity == 0U || source == nullptr) {
        return false;
    }
    size_t length = 0U;
    while (length < capacity && source[length] != '\0') {
        ++length;
    }
    if (length == capacity) {
        return false;
    }
    for (size_t index = 0U; index <= length; ++index) {
        destination[index] = source[index];
    }
    return true;
}

bool RunReentrantDestroySelfTest() {
    HookselfConfig config{};
    hookself_framework_default_config(&config);
    config.log_level = HOOKSELF_LOG_TRACE;

    HookselfFramework* framework = nullptr;
    if (hookself_framework_create(&config, &framework) != HOOKSELF_OK ||
        framework == nullptr) {
        hookself_framework_destroy(framework);
        return false;
    }

    HookselfSyscallRule rule{};
    rule.struct_size = sizeof(rule);
    rule.rule_id = 0x6491U;
    rule.syscall_number = __NR_getpid;
    rule.action = HOOKSELF_SYSCALL_OBSERVE;
    rule.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
    HookselfRuleHandle handle = HOOKSELF_INVALID_RULE_HANDLE;
    ReentrantDestroyCapture capture{framework, 0U, 0U};
    const int32_t register_result = hookself_framework_register_syscall_rule(
            framework, &rule, 1, &handle);
    const int32_t sink_result = register_result == HOOKSELF_OK
                                        ? hookself_framework_set_log_sink(
                                                  framework, DestroyFromSink,
                                                  &capture)
                                        : register_result;
    const int32_t start_result = sink_result == HOOKSELF_OK
                                         ? hookself_framework_start(framework)
                                         : sink_result;
    if (start_result == HOOKSELF_OK) {
        (void)syscall(__NR_getpid);
    }
    size_t consumed = 0U;
    size_t emitted = 0U;
    const int32_t drain_result = start_result == HOOKSELF_OK
                                         ? hookself_framework_drain_logs(
                                                   framework, 128U, &consumed,
                                                   &emitted)
                                         : start_result;

    if (capture.framework != nullptr) {
        (void)hookself_framework_stop(capture.framework);
        hookself_framework_destroy(capture.framework);
        capture.framework = nullptr;
    }
    return register_result == HOOKSELF_OK &&
           handle != HOOKSELF_INVALID_RULE_HANDLE &&
           sink_result == HOOKSELF_OK && start_result == HOOKSELF_OK &&
           drain_result == HOOKSELF_E_INVALID_STATE && consumed >= 1U &&
           emitted == 1U && capture.callbacks == 1U &&
           capture.callbacks_after_destroy == 0U;
}

bool ReadVirtualContent(const char* path, const uint8_t* expected,
                        size_t expected_size) {
    uint8_t buffer[64]{};
    if (expected_size > sizeof(buffer)) {
        return false;
    }
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    const ssize_t count = read(fd, buffer, sizeof(buffer));
    const int close_result = close(fd);
    return count == static_cast<ssize_t>(expected_size) &&
           close_result == 0 &&
           std::memcmp(buffer, expected, expected_size) == 0;
}

bool RunPublishCacheSelfTest(const char* virtual_backing_dir) {
    if (virtual_backing_dir == nullptr || virtual_backing_dir[0] != '/') {
        return false;
    }
    constexpr char kGuestPath[] = "/proc/self/hookself-facade-cache";
    constexpr uint8_t kInitialContent[] = {'o', 'l', 'd'};
    constexpr uint8_t kPublishedContent[] = {'n', 'e', 'w', '-', 'c', 'a',
                                              'c', 'h', 'e'};

    HookselfVirtualFile file{};
    file.struct_size = sizeof(file);
    file.file_id = 0x6492U;
    file.provider = HOOKSELF_VFILE_DYNAMIC_SNAPSHOT;
    file.mode = 0444U;
    file.initial_content = kInitialContent;
    file.initial_content_size = sizeof(kInitialContent);
    if (!CopyString(file.guest_path, sizeof(file.guest_path), kGuestPath)) {
        return false;
    }

    HookselfConfig config{};
    hookself_framework_default_config(&config);
    config.flags |= HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES;
    config.virtual_file_count = 1U;
    config.virtual_files = &file;
    if (!CopyString(config.virtual_backing_dir,
                    sizeof(config.virtual_backing_dir),
                    virtual_backing_dir)) {
        return false;
    }

    HookselfFramework* framework = nullptr;
    const int32_t create_result = hookself_framework_create(
            &config, &framework);
    const int32_t first_start = create_result == HOOKSELF_OK
                                        ? hookself_framework_start(framework)
                                        : create_result;
    SetVirtualPublishPostCommitFailureForSelfTest(true);
    const int32_t publish_result = first_start == HOOKSELF_OK
                                           ? hookself_framework_publish_virtual_file(
                                                     framework, file.file_id,
                                                     kPublishedContent,
                                                     sizeof(kPublishedContent))
                                           : first_start;
    SetVirtualPublishPostCommitFailureForSelfTest(false);
    const bool first_content = publish_result == HOOKSELF_E_INTERNAL &&
            ReadVirtualContent(kGuestPath, kPublishedContent,
                               sizeof(kPublishedContent));
    const int32_t first_stop = first_start == HOOKSELF_OK
                                       ? hookself_framework_stop(framework)
                                       : first_start;

    HookselfSyscallRule rule{};
    rule.struct_size = sizeof(rule);
    rule.rule_id = 0x6493U;
    rule.syscall_number = __NR_getppid;
    rule.action = HOOKSELF_SYSCALL_OBSERVE;
    rule.phase_mask = HOOKSELF_SYSCALL_PHASE_BOTH;
    HookselfRuleHandle handle = HOOKSELF_INVALID_RULE_HANDLE;
    const int32_t mutate_result = first_stop == HOOKSELF_OK
                                          ? hookself_framework_register_syscall_rule(
                                                    framework, &rule, 1, &handle)
                                          : first_stop;
    const int32_t second_start = mutate_result == HOOKSELF_OK
                                         ? hookself_framework_start(framework)
                                         : mutate_result;
    const bool rebuilt_content = second_start == HOOKSELF_OK &&
            ReadVirtualContent(kGuestPath, kPublishedContent,
                               sizeof(kPublishedContent));
    const int32_t second_stop = second_start == HOOKSELF_OK
                                        ? hookself_framework_stop(framework)
                                        : second_start;
    hookself_framework_destroy(framework);
    return create_result == HOOKSELF_OK && first_start == HOOKSELF_OK &&
           first_content && first_stop == HOOKSELF_OK &&
           mutate_result == HOOKSELF_OK &&
           handle != HOOKSELF_INVALID_RULE_HANDLE &&
           second_start == HOOKSELF_OK && rebuilt_content &&
           second_stop == HOOKSELF_OK;
}

}  // namespace

bool RunFrameworkFacadeRuntimeSelfTest(const char* virtual_backing_dir) {
    return RunReentrantDestroySelfTest() &&
           RunPublishCacheSelfTest(virtual_backing_dir);
}

}  // namespace hookself::internal
