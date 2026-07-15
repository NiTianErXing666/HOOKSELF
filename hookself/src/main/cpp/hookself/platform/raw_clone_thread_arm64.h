#pragma once

#if !defined(__aarch64__)
#error "hookself raw clone trampoline is currently arm64-only"
#endif

#include <cstdint>

namespace hookself::platform {

using RawThreadEntry = int (*)(void*);

// Creates a thread with clone(2) and starts it on caller-owned stack storage.
// The child executes only the supplied entry and raw exit(2); it does not pass
// through libc's clone trampoline. Returns a positive TID or a raw -errno.
extern "C" long HookselfRawCloneThread(RawThreadEntry entry, void* argument,
                                       void* stack_top,
                                       uint64_t clone_flags) noexcept;

}  // namespace hookself::platform
