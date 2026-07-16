#ifndef HOOKSELF_ELF_HOOK_H
#define HOOKSELF_ELF_HOOK_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(HOOKSELF_ELF_BUILDING_LIBRARY)
#define HOOKSELF_ELF_API __declspec(dllexport)
#else
#define HOOKSELF_ELF_API __declspec(dllimport)
#endif
#elif defined(__GNUC__)
#define HOOKSELF_ELF_API __attribute__((visibility("default")))
#else
#define HOOKSELF_ELF_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define HOOKSELF_ELF_ABI_VERSION 1U
#define HOOKSELF_ELF_INVALID_HANDLE UINT64_C(0)
#define HOOKSELF_ELF_PATH_CAPACITY 512U
#define HOOKSELF_ELF_SYMBOL_CAPACITY 256U

typedef uint64_t HookselfElfHandle;

typedef enum HookselfElfResult {
    HOOKSELF_ELF_OK = 0,
    HOOKSELF_ELF_E_INVALID_ARGUMENT = -30001,
    HOOKSELF_ELF_E_ABI_MISMATCH = -30002,
    HOOKSELF_ELF_E_UNSUPPORTED_ARCH = -30003,
    HOOKSELF_ELF_E_MODULE_NOT_FOUND = -30004,
    HOOKSELF_ELF_E_MODULE_AMBIGUOUS = -30005,
    HOOKSELF_ELF_E_MALFORMED_ELF = -30006,
    HOOKSELF_ELF_E_UNSUPPORTED_ELF = -30007,
    HOOKSELF_ELF_E_SYMBOL_NOT_FOUND = -30008,
    HOOKSELF_ELF_E_RELOCATION_NOT_FOUND = -30009,
    HOOKSELF_ELF_E_ALREADY_INSTALLED = -30010,
    HOOKSELF_ELF_E_NOT_FOUND = -30011,
    HOOKSELF_ELF_E_TOO_MANY_SLOTS = -30012,
    HOOKSELF_ELF_E_PROTECTION = -30013,
    HOOKSELF_ELF_E_CONFLICT = -30014,
    HOOKSELF_ELF_E_BUSY = -30015,
    HOOKSELF_ELF_E_MODULE_UNLOADED = -30016,
    HOOKSELF_ELF_E_UNSUPPORTED_SYMBOL = -30017,
    HOOKSELF_ELF_E_INTERNAL = -30018,
    HOOKSELF_ELF_E_RECOVERY_REQUIRED = -30019,
} HookselfElfResult;

typedef enum HookselfElfState {
    HOOKSELF_ELF_STATE_ACTIVE = 1,
    HOOKSELF_ELF_STATE_REMOVED = 2,
    HOOKSELF_ELF_STATE_ORPHANED = 3,
    HOOKSELF_ELF_STATE_RECOVERY_REQUIRED = 4,
} HookselfElfState;

enum HookselfElfFeature {
    HOOKSELF_ELF_FEATURE_LOADED_MODULE_LOOKUP = UINT64_C(1) << 0,
    HOOKSELF_ELF_FEATURE_MEMORY_DYNSYM = UINT64_C(1) << 1,
    HOOKSELF_ELF_FEATURE_GNU_HASH = UINT64_C(1) << 2,
    HOOKSELF_ELF_FEATURE_SYSV_HASH = UINT64_C(1) << 3,
    HOOKSELF_ELF_FEATURE_ARM64_JUMP_SLOT = UINT64_C(1) << 4,
    HOOKSELF_ELF_FEATURE_ATOMIC_POINTER_CAS = UINT64_C(1) << 5,
    HOOKSELF_ELF_FEATURE_RELRO_RESTORE = UINT64_C(1) << 6,
    HOOKSELF_ELF_FEATURE_THREAD_SAFE_REGISTRY = UINT64_C(1) << 7,
    HOOKSELF_ELF_FEATURE_RECOVERABLE_TRANSACTION = UINT64_C(1) << 8,
};

enum HookselfElfModuleFlags {
    HOOKSELF_ELF_MODULE_F_MAIN_EXECUTABLE = 1U << 0,
    HOOKSELF_ELF_MODULE_F_PATH_TRUNCATED = 1U << 1,
    HOOKSELF_ELF_MODULE_F_GNU_HASH = 1U << 2,
    HOOKSELF_ELF_MODULE_F_SYSV_HASH = 1U << 3,
    HOOKSELF_ELF_MODULE_F_GNU_RELRO = 1U << 4,
};

enum HookselfElfSymbolFlags {
    HOOKSELF_ELF_SYMBOL_F_GNU_HASH = 1U << 0,
    HOOKSELF_ELF_SYMBOL_F_SYSV_HASH = 1U << 1,
    HOOKSELF_ELF_SYMBOL_F_ABSOLUTE = 1U << 2,
    HOOKSELF_ELF_SYMBOL_F_WEAK = 1U << 3,
    HOOKSELF_ELF_SYMBOL_F_PATH_TRUNCATED = 1U << 4,
};

enum HookselfElfInfoFlags {
    HOOKSELF_ELF_INFO_F_JUMP_SLOT = 1U << 0,
    HOOKSELF_ELF_INFO_F_GNU_RELRO = 1U << 1,
    HOOKSELF_ELF_INFO_F_PATH_TRUNCATED = 1U << 2,
};

/* Reserved fields and flags must be zero. */
typedef struct HookselfElfOptions {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t flags;
    uint32_t reserved[5];
} HookselfElfOptions;

typedef struct HookselfElfCapabilities {
    uint32_t struct_size;
    uint32_t abi_version;
    uint64_t features;
    uint32_t pointer_size;
    uint32_t max_active_hooks;
    uint32_t max_slots_per_hook;
    uint32_t path_capacity;
    uint32_t symbol_capacity;
    uint32_t reserved[5];
} HookselfElfCapabilities;

typedef struct HookselfElfModuleInfo {
    uint32_t struct_size;
    uint32_t flags;
    uintptr_t load_bias;
    uintptr_t load_start;
    uintptr_t load_end;
    uintptr_t program_headers;
    uint32_t program_header_count;
    uint32_t reserved0;
    char path[HOOKSELF_ELF_PATH_CAPACITY];
    uint64_t reserved[4];
} HookselfElfModuleInfo;

typedef struct HookselfElfSymbolInfo {
    uint32_t struct_size;
    uint32_t flags;
    uintptr_t address;
    uint64_t size;
    uintptr_t module_load_bias;
    uint32_t symbol_index;
    uint32_t binding;
    uint32_t type;
    uint32_t visibility;
    uint32_t section_index;
    uint32_t reserved0;
    char module_path[HOOKSELF_ELF_PATH_CAPACITY];
    uint64_t reserved[4];
} HookselfElfSymbolInfo;

typedef struct HookselfElfInfo {
    uint32_t struct_size;
    uint32_t state;
    HookselfElfHandle handle;
    uintptr_t module_load_bias;
    uintptr_t replacement;
    uintptr_t original;
    uintptr_t first_slot;
    uint32_t slot_count;
    uint32_t flags;
    char module_path[HOOKSELF_ELF_PATH_CAPACITY];
    char symbol_name[HOOKSELF_ELF_SYMBOL_CAPACITY];
    uint64_t reserved[4];
} HookselfElfInfo;

HOOKSELF_ELF_API uint32_t hookself_elf_get_abi_version(void);
HOOKSELF_ELF_API void hookself_elf_default_options(
        HookselfElfOptions* options);
HOOKSELF_ELF_API int32_t hookself_elf_validate_options(
        const HookselfElfOptions* options);
HOOKSELF_ELF_API int32_t hookself_elf_get_capabilities(
        HookselfElfCapabilities* capabilities);

/* These APIs inspect modules already present in dl_iterate_phdr; they do not
 * load modules or subscribe to later dlopen events. A null or empty name
 * selects the first (main-program) loader entry. A basename must identify one
 * entry. A name containing '/' must uniquely byte-match dlpi_name; paths are
 * not canonicalized and DT_SONAME is not used. On failure, info is unchanged. */
HOOKSELF_ELF_API int32_t hookself_elf_get_module_info(
        const char* module_name, HookselfElfModuleInfo* info);
HOOKSELF_ELF_API int32_t hookself_elf_resolve_symbol(
        const char* module_name, const char* symbol_name,
        HookselfElfSymbolInfo* info);

/* resolve_symbol searches defined .dynsym entries in the selected module. It
 * does not perform global dlsym lookup or symbol-version selection. TLS and
 * GNU IFUNC resolver addresses are reported as UNSUPPORTED_SYMBOL. The caller
 * keeps the selected module loaded while using a returned address. */

/* Installs an ARM64 function R_AARCH64_JUMP_SLOT hook in one currently loaded
 * caller/consumer module (not the symbol-provider module). All matching PLT/GOT
 * slots are committed as one rollback-capable transaction. original is
 * release-stored before a slot can expose replacement; handle is written only
 * after the complete transaction. Ordinary failures preserve both outputs.
 *
 * RECOVERY_REQUIRED is the sole exception: a valid handle and original are
 * returned because a rare page-protection recovery still needs remove(handle)
 * or unhook(module, symbol). This prevents a modified slot from becoming
 * unreachable after an error.
 *
 * The caller must retain the consumer module's loader reference and must not
 * race install/remove with dlclose or same-address reload. After remove, wait
 * for in-flight replacement calls before unloading replacement/provider code
 * or libhookself_elf itself. In a multi-threaded fork child, exec before using
 * APIs that enter the Android loader; get_info is loader-free. */
HOOKSELF_ELF_API int32_t hookself_elf_install(
        const char* module_name, const char* symbol_name, void* replacement,
        const HookselfElfOptions* options, void** original,
        HookselfElfHandle* handle);

/* Dobby-style convenience wrapper. Remove it with unhook(module, symbol). */
HOOKSELF_ELF_API int32_t hookself_elf_hook(
        const char* module_name, const char* symbol_name, void* replacement,
        void** original);

HOOKSELF_ELF_API int32_t hookself_elf_remove(HookselfElfHandle handle);
HOOKSELF_ELF_API int32_t hookself_elf_unhook(
        const char* module_name, const char* symbol_name);
HOOKSELF_ELF_API int32_t hookself_elf_find(
        const char* module_name, const char* symbol_name,
        HookselfElfHandle* handle);
/* find returns ACTIVE and RECOVERY_REQUIRED handles. It clears handle to
 * INVALID_HANDLE for a valid query that is not found. */
HOOKSELF_ELF_API int32_t hookself_elf_get_info(
        HookselfElfHandle handle, HookselfElfInfo* info);

HOOKSELF_ELF_API const char* hookself_elf_result_string(int32_t result);

#ifdef __cplusplus
}
#endif

#endif
