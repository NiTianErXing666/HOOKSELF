#ifndef HOOKSELF_FRAMEWORK_H
#define HOOKSELF_FRAMEWORK_H

#include "hookself/public_api.h"

#ifndef HOOKSELF_API
#if defined(_WIN32)
#if defined(HOOKSELF_BUILDING_LIBRARY)
#define HOOKSELF_API __declspec(dllexport)
#else
#define HOOKSELF_API __declspec(dllimport)
#endif
#elif defined(__GNUC__)
#define HOOKSELF_API __attribute__((visibility("default")))
#else
#define HOOKSELF_API
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque owner of a HookSelf rule registry and its lazily-created runtime. */
typedef struct HookselfFramework HookselfFramework;

/** Opaque rule handle. Zero is never returned as a valid handle. */
typedef uint64_t HookselfRuleHandle;

#define HOOKSELF_INVALID_RULE_HANDLE UINT64_C(0)

/** Selects the registry namespace used by hookself_framework_find_rule(). */
typedef enum HookselfRuleKind {
    HOOKSELF_RULE_KIND_PATH = 1,
    HOOKSELF_RULE_KIND_SYSCALL = 2,
} HookselfRuleKind;

/**
 * Optional settings for hookself_framework_register_redirect().
 *
 * Pass NULL to use the defaults. A zero rule_id requests an automatically
 * allocated public rule id. A supplied rule id must be below
 * HOOKSELF_BUILTIN_RULE_ID_MIN. operation_mask must be nonzero and reserved
 * fields must be zero when this structure is supplied.
 */
typedef struct HookselfRedirectOptions {
    uint32_t struct_size;
    uint32_t rule_id;
    int32_t priority;
    uint32_t operation_mask;
    uint32_t flags;
    uint32_t reserved[4];
} HookselfRedirectOptions;

/** Initializes a fail-closed-friendly base configuration for the facade. */
HOOKSELF_API void hookself_framework_default_config(HookselfConfig* config);

/** Initializes redirect defaults: automatic id, all operations, no flags. */
HOOKSELF_API void hookself_framework_default_redirect_options(
        HookselfRedirectOptions* options);

/**
 * Creates a facade and deep-copies config, including all path rules, syscall
 * rules, virtual-file descriptors, and virtual-file initial content.
 *
 * The HookselfRuntime is created lazily by the first successful start. The
 * rule registry remains editable after a failed start. A selective runtime
 * permanently freezes it after the first successful start. A full-ptrace
 * runtime permits changes only after stop; a successful change then discards
 * the stopped runtime so the next start can rebuild it. Disallowed mutations
 * return HOOKSELF_E_INVALID_STATE.
 */
HOOKSELF_API int32_t hookself_framework_create(
        const HookselfConfig* config, HookselfFramework** framework);

/**
 * Destroys the runtime and all facade-owned copies. Use one destroy caller and
 * do not begin new facade calls after requesting destruction.
 */
HOOKSELF_API void hookself_framework_destroy(HookselfFramework* framework);

/** Registers a complete syscall rule and returns its opaque handle. */
HOOKSELF_API int32_t hookself_framework_register_syscall_rule(
        HookselfFramework* framework, const HookselfSyscallRule* rule,
        int32_t enabled, HookselfRuleHandle* handle);

/** Registers a public-id path rule and returns its opaque handle. */
HOOKSELF_API int32_t hookself_framework_register_path_rule(
        HookselfFramework* framework, const HookselfPathRule* rule,
        int32_t enabled, HookselfRuleHandle* handle);

/**
 * Registers a path redirect without requiring the caller to assemble a
 * HookselfPathRule. The facade enables HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT
 * for facade-registered path policies, but never changes failure_mode.
 */
HOOKSELF_API int32_t hookself_framework_register_redirect(
        HookselfFramework* framework, const char* guest_prefix,
        const char* host_prefix, const HookselfRedirectOptions* options,
        int32_t enabled, HookselfRuleHandle* handle);

/** Finds an initial or subsequently registered rule by kind and rule id. */
HOOKSELF_API int32_t hookself_framework_find_rule(
        const HookselfFramework* framework, HookselfRuleKind kind,
        uint32_t rule_id, HookselfRuleHandle* handle);

/** Removes a registered path or syscall rule. */
HOOKSELF_API int32_t hookself_framework_unregister_rule(
        HookselfFramework* framework, HookselfRuleHandle handle);

/** Changes whether a rule is active in the next runtime configuration. */
HOOKSELF_API int32_t hookself_framework_set_rule_enabled(
        HookselfFramework* framework, HookselfRuleHandle handle,
        int32_t enabled);

/** Returns 0 or 1 through enabled for a live rule handle. */
HOOKSELF_API int32_t hookself_framework_is_rule_enabled(
        const HookselfFramework* framework, HookselfRuleHandle handle,
        int32_t* enabled);

/**
 * Starts policy handling. Calls are idempotent while already running, and a
 * stopped runtime can be started again. Disabled rules are published as PASS;
 * in selective mode this retains each registered syscall in the first plan.
 */
HOOKSELF_API int32_t hookself_framework_start(HookselfFramework* framework);

/** Stops policy handling. Calls before start or after stop are idempotent. */
HOOKSELF_API int32_t hookself_framework_stop(HookselfFramework* framework);

/** Returns facade/runtime state; a not-yet-started facade is CONFIGURED. */
HOOKSELF_API int32_t hookself_framework_get_state(
        const HookselfFramework* framework, int32_t* state);

/** Forwards runtime statistics, or returns zero CONFIGURED stats before start. */
HOOKSELF_API int32_t hookself_framework_get_stats(
        const HookselfFramework* framework, HookselfStats* stats);

/** Forwards raw event reads. Returns zero before the runtime exists. */
HOOKSELF_API size_t hookself_framework_read_events(
        HookselfFramework* framework, HookselfEvent* events, size_t capacity);

/** Stores the sink before start and forwards it once a runtime exists. */
HOOKSELF_API int32_t hookself_framework_set_log_sink(
        HookselfFramework* framework, HookselfLogSink sink, void* user_data);

/** Forwards queued-event log draining to the runtime. */
HOOKSELF_API int32_t hookself_framework_drain_logs(
        HookselfFramework* framework, size_t max_events,
        size_t* consumed_events, size_t* emitted_logs);

/** Forwards a dynamic virtual-file snapshot publication. */
HOOKSELF_API int32_t hookself_framework_publish_virtual_file(
        HookselfFramework* framework, uint32_t file_id,
        const uint8_t* content, size_t content_size);

/** Forwards regeneration of a provider-backed virtual file. */
HOOKSELF_API int32_t hookself_framework_refresh_virtual_file(
        HookselfFramework* framework, uint32_t file_id);

#ifdef __cplusplus
}
#endif

#endif
