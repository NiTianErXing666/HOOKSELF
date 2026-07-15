#include "framework_facade_lifetime_selftest.h"

#include <pthread.h>
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <new>

#include "hookself/framework.h"

namespace hookself::internal {
namespace {

constexpr uint32_t kEntryDestroyStressIterations = 32U;

bool WaitForAtomicValue(const uint32_t* value, uint32_t expected,
                        uint32_t timeout_ms) {
    for (uint32_t elapsed = 0; elapsed < timeout_ms; ++elapsed) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) == expected) {
            return true;
        }
        usleep(1000);
    }
    return __atomic_load_n(value, __ATOMIC_ACQUIRE) == expected;
}

struct EntryDestroyStress {
    HookselfFramework* framework;
    HookselfStats* stats;
    void* protected_page;
    size_t page_size;
    uint32_t fault_entered;
    uint32_t release_fault;
    uint32_t call_returned;
    uint32_t destroy_started;
    uint32_t destroy_returned;
    int32_t call_result;
    uint32_t returned_state;
};

EntryDestroyStress* gEntryDestroyStress = nullptr;
struct sigaction gPreviousSegvAction {};

void EntryDestroySegvHandler(int signal_number, siginfo_t* info,
                             void* signal_context) {
    EntryDestroyStress* const stress = __atomic_load_n(
            &gEntryDestroyStress, __ATOMIC_ACQUIRE);
    const uintptr_t fault_address = info == nullptr
                                            ? 0U
                                            : reinterpret_cast<uintptr_t>(
                                                      info->si_addr);
    const uintptr_t page_start = stress == nullptr
                                         ? 0U
                                         : reinterpret_cast<uintptr_t>(
                                                   stress->protected_page);
    if (stress != nullptr && info != nullptr && fault_address >= page_start &&
        fault_address - page_start < stress->page_size) {
        __atomic_store_n(&stress->fault_entered, 1U, __ATOMIC_RELEASE);
        while (__atomic_load_n(&stress->release_fault,
                               __ATOMIC_ACQUIRE) == 0U) {
            __asm__ volatile("yield" ::: "memory");
        }
        return;
    }

    if ((gPreviousSegvAction.sa_flags & SA_SIGINFO) != 0 &&
        gPreviousSegvAction.sa_sigaction != nullptr) {
        gPreviousSegvAction.sa_sigaction(
                signal_number, info, signal_context);
        return;
    }
    if (gPreviousSegvAction.sa_handler == SIG_IGN) {
        return;
    }
    if (gPreviousSegvAction.sa_handler != SIG_DFL &&
        gPreviousSegvAction.sa_handler != nullptr) {
        gPreviousSegvAction.sa_handler(signal_number);
        return;
    }
    struct sigaction default_action {};
    default_action.sa_handler = SIG_DFL;
    sigemptyset(&default_action.sa_mask);
    (void)sigaction(signal_number, &default_action, nullptr);
    (void)raise(signal_number);
    _exit(128 + signal_number);
}

void* RunFacadeEntry(void* argument) {
    auto* stress = static_cast<EntryDestroyStress*>(argument);
    stress->call_result = hookself_framework_get_stats(
            stress->framework, stress->stats);
    stress->returned_state = stress->call_result == HOOKSELF_OK
                                     ? stress->stats->state
                                     : HOOKSELF_STATE_IDLE;
    __atomic_store_n(&stress->call_returned, 1U, __ATOMIC_RELEASE);
    return nullptr;
}

void* DestroyFacade(void* argument) {
    auto* stress = static_cast<EntryDestroyStress*>(argument);
    __atomic_store_n(&stress->destroy_started, 1U, __ATOMIC_RELEASE);
    hookself_framework_destroy(stress->framework);
    __atomic_store_n(&stress->destroy_returned, 1U, __ATOMIC_RELEASE);
    return nullptr;
}

bool ReleaseProtectedPage(void* page, size_t page_size) {
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE) == 0) {
        return true;
    }
    void* const replacement = mmap(
            page, page_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return replacement == page;
}

bool RunEntryDestroyIteration() {
    HookselfConfig config{};
    hookself_framework_default_config(&config);
    HookselfFramework* framework = nullptr;
    if (hookself_framework_create(&config, &framework) != HOOKSELF_OK ||
        framework == nullptr) {
        hookself_framework_destroy(framework);
        return false;
    }

    const long page_size_result = sysconf(_SC_PAGESIZE);
    if (page_size_result <= 0) {
        hookself_framework_destroy(framework);
        return false;
    }
    const size_t page_size = static_cast<size_t>(page_size_result);
    void* const mapping = mmap(nullptr, page_size * 2U,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        hookself_framework_destroy(framework);
        return false;
    }

    auto* const bytes = static_cast<uint8_t*>(mapping);
    auto* const stats = ::new (bytes + page_size - 8U) HookselfStats{};
    stats->struct_size = sizeof(HookselfStats);
    void* const protected_page = bytes + page_size;
    if (mprotect(protected_page, page_size, PROT_NONE) != 0) {
        munmap(mapping, page_size * 2U);
        hookself_framework_destroy(framework);
        return false;
    }

    EntryDestroyStress stress{};
    stress.framework = framework;
    stress.stats = stats;
    stress.protected_page = protected_page;
    stress.page_size = page_size;
    stress.call_result = HOOKSELF_E_INTERNAL;
    __atomic_store_n(&gEntryDestroyStress, &stress, __ATOMIC_RELEASE);

    pthread_t call_thread{};
    pthread_t destroy_thread{};
    const int call_thread_result = pthread_create(
            &call_thread, nullptr, RunFacadeEntry, &stress);
    const bool fault_entered = call_thread_result == 0 &&
            WaitForAtomicValue(&stress.fault_entered, 1U, 5000U);
    const int destroy_thread_result = fault_entered
                                              ? pthread_create(
                                                        &destroy_thread, nullptr,
                                                        DestroyFacade, &stress)
                                              : -1;
    const bool destroy_started = destroy_thread_result == 0 &&
            WaitForAtomicValue(&stress.destroy_started, 1U, 5000U);
    bool registry_removed = false;
    bool entrant_results_valid = true;
    for (uint32_t elapsed = 0; destroy_started && elapsed < 5000U;
         ++elapsed) {
        int32_t state = HOOKSELF_STATE_IDLE;
        const int32_t result = hookself_framework_get_state(
                framework, &state);
        if (result == HOOKSELF_E_INVALID_STATE) {
            registry_removed = true;
            break;
        }
        if (result != HOOKSELF_OK || state != HOOKSELF_STATE_CONFIGURED) {
            entrant_results_valid = false;
            break;
        }
        usleep(1000);
    }
    const bool destroy_waited = registry_removed && entrant_results_valid &&
            __atomic_load_n(&stress.destroy_returned,
                            __ATOMIC_ACQUIRE) == 0U;
    const bool page_released =
            ReleaseProtectedPage(protected_page, page_size);
    __atomic_store_n(&stress.release_fault, 1U, __ATOMIC_RELEASE);

    const int call_join_result = call_thread_result == 0
                                         ? pthread_join(call_thread, nullptr)
                                         : -1;
    const int destroy_join_result = destroy_thread_result == 0
                                            ? pthread_join(
                                                      destroy_thread, nullptr)
                                            : -1;
    __atomic_store_n(&gEntryDestroyStress, nullptr, __ATOMIC_RELEASE);

    if (destroy_thread_result != 0) {
        hookself_framework_destroy(framework);
    }
    munmap(mapping, page_size * 2U);
    return call_thread_result == 0 && fault_entered &&
           destroy_thread_result == 0 && destroy_started && registry_removed &&
           entrant_results_valid && destroy_waited && page_released &&
           call_join_result == 0 &&
           destroy_join_result == 0 &&
           __atomic_load_n(&stress.call_returned,
                           __ATOMIC_ACQUIRE) != 0U &&
           __atomic_load_n(&stress.destroy_returned,
                           __ATOMIC_ACQUIRE) != 0U &&
           stress.call_result == HOOKSELF_OK &&
           stress.returned_state == HOOKSELF_STATE_CONFIGURED;
}

}  // namespace

bool RunFrameworkFacadeLifetimeSelfTest() {
    struct sigaction action {};
    action.sa_sigaction = EntryDestroySegvHandler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, &gPreviousSegvAction) != 0) {
        return false;
    }
    bool passed = true;
    for (uint32_t iteration = 0;
         iteration < kEntryDestroyStressIterations; ++iteration) {
        passed = RunEntryDestroyIteration() && passed;
    }
    const bool restored =
            sigaction(SIGSEGV, &gPreviousSegvAction, nullptr) == 0;
    return passed && restored;
}

}  // namespace hookself::internal
