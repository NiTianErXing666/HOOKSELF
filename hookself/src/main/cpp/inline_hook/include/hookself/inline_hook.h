#ifndef HOOKSELF_INLINE_HOOK_H
#define HOOKSELF_INLINE_HOOK_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(HOOKSELF_INLINE_BUILDING_LIBRARY)
#define HOOKSELF_INLINE_API __declspec(dllexport)
#else
#define HOOKSELF_INLINE_API __declspec(dllimport)
#endif
#elif defined(__GNUC__)
#define HOOKSELF_INLINE_API __attribute__((visibility("default")))
#else
#define HOOKSELF_INLINE_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define HOOKSELF_INLINE_ABI_VERSION 1U
#define HOOKSELF_INLINE_INVALID_HANDLE UINT64_C(0)

typedef uint64_t HookselfInlineHandle;

typedef enum HookselfInlineResult {
    HOOKSELF_INLINE_OK = 0,
    HOOKSELF_INLINE_E_INVALID_ARGUMENT = -20001,
    HOOKSELF_INLINE_E_ABI_MISMATCH = -20002,
    HOOKSELF_INLINE_E_UNSUPPORTED_ARCH = -20003,
    HOOKSELF_INLINE_E_ALREADY_INSTALLED = -20004,
    HOOKSELF_INLINE_E_NOT_FOUND = -20005,
    HOOKSELF_INLINE_E_NO_MEMORY = -20006,
    HOOKSELF_INLINE_E_RANGE = -20007,
    HOOKSELF_INLINE_E_RELOCATION = -20008,
    HOOKSELF_INLINE_E_PROTECTION = -20009,
    HOOKSELF_INLINE_E_CONFLICT = -20010,
    HOOKSELF_INLINE_E_BUSY = -20011,
    HOOKSELF_INLINE_E_INTERNAL = -20012,
} HookselfInlineResult;

typedef enum HookselfInlineState {
    HOOKSELF_INLINE_STATE_ACTIVE = 1,
    HOOKSELF_INLINE_STATE_REMOVED = 2,
} HookselfInlineState;

enum HookselfInlineFeature {
    HOOKSELF_INLINE_FEATURE_ATOMIC_ARM64_BRANCH = UINT64_C(1) << 0,
    HOOKSELF_INLINE_FEATURE_NEAR_BRIDGE = UINT64_C(1) << 1,
    HOOKSELF_INLINE_FEATURE_ORIGINAL_TRAMPOLINE = UINT64_C(1) << 2,
    HOOKSELF_INLINE_FEATURE_PC_RELATIVE_RELOCATION = UINT64_C(1) << 3,
    HOOKSELF_INLINE_FEATURE_BTI_ENTRY = UINT64_C(1) << 4,
    HOOKSELF_INLINE_FEATURE_PAC_ENTRY = UINT64_C(1) << 5,
    HOOKSELF_INLINE_FEATURE_RETAINED_TRAMPOLINE = UINT64_C(1) << 6,
    HOOKSELF_INLINE_FEATURE_THREAD_SAFE_REGISTRY = UINT64_C(1) << 7,
};

enum HookselfInlineInfoFlags {
    HOOKSELF_INLINE_INFO_F_PATCH_AFTER_BTI = 1U << 0,
    HOOKSELF_INLINE_INFO_F_PATCH_AFTER_PAC = 1U << 1,
    HOOKSELF_INLINE_INFO_F_NEAR_BRIDGE = 1U << 2,
    HOOKSELF_INLINE_INFO_F_USES_X17 = 1U << 3,
    HOOKSELF_INLINE_INFO_F_RELOCATION_EXPANDED = 1U << 4,
    HOOKSELF_INLINE_INFO_F_TRAMPOLINE_RETAINED = 1U << 5,
};

/* Reserved fields and flags must be zero. */
typedef struct HookselfInlineOptions {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t flags;
    uint32_t reserved[5];
} HookselfInlineOptions;

typedef struct HookselfInlineCapabilities {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t features;
    uint32_t instruction_size;
    uint32_t patch_size;
    uint64_t near_branch_range;
    uint32_t max_active_hooks;
    uint32_t reserved[5];
} HookselfInlineCapabilities;

typedef struct HookselfInlineInfo {
    uint32_t struct_size;
    uint32_t state;
    HookselfInlineHandle handle;
    uintptr_t target;
    uintptr_t replacement;
    uintptr_t original;
    uintptr_t patch_address;
    uintptr_t bridge_address;
    uint32_t patch_size;
    uint32_t relocated_size;
    uint32_t flags;
    uint32_t reserved[5];
} HookselfInlineInfo;

HOOKSELF_INLINE_API uint32_t hookself_inline_get_abi_version(void);
HOOKSELF_INLINE_API void hookself_inline_default_options(
        HookselfInlineOptions* options);
HOOKSELF_INLINE_API int32_t hookself_inline_validate_options(
        const HookselfInlineOptions* options);
HOOKSELF_INLINE_API int32_t hookself_inline_get_capabilities(
        HookselfInlineCapabilities* capabilities);

/*
 * Installs a hook at an ARM64 function entry. Mid-function instruction hooks
 * are outside this ABI's calling-convention contract. The returned original
 * function trampoline page remains mapped after removal. Calling it still
 * requires the target mapping and its referenced code/data to remain mapped.
 * The replacement mapping must outlive its in-flight calls. On success,
 * original is release-published before the target patch can execute and handle
 * is then returned. At a failing return, both output values equal their input
 * values.
 */
HOOKSELF_INLINE_API int32_t hookself_inline_install(
        void* target, void* replacement, const HookselfInlineOptions* options,
        void** original, HookselfInlineHandle* handle);

/* Dobby-style convenience wrapper. Remove it later with unhook(target). */
HOOKSELF_INLINE_API int32_t hookself_inline_hook(
        void* target, void* replacement, void** original);

HOOKSELF_INLINE_API int32_t hookself_inline_remove(
        HookselfInlineHandle handle);
HOOKSELF_INLINE_API int32_t hookself_inline_unhook(void* target);

HOOKSELF_INLINE_API int32_t hookself_inline_find(
        const void* target, HookselfInlineHandle* handle);
HOOKSELF_INLINE_API int32_t hookself_inline_get_info(
        HookselfInlineHandle handle, HookselfInlineInfo* info);

HOOKSELF_INLINE_API const char* hookself_inline_result_string(int32_t result);

#ifdef __cplusplus
}
#endif

#endif
