#ifndef HOOKSELF_PUBLIC_API_H
#define HOOKSELF_PUBLIC_API_H

#include <stddef.h>
#include <stdint.h>

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

#ifdef __cplusplus
extern "C" {
#endif

#define HOOKSELF_ABI_VERSION 6U
#define HOOKSELF_PATH_CAPACITY 512U
#define HOOKSELF_EVENT_PATH_CAPACITY 512U
#define HOOKSELF_MAX_PATH_RULES 64U
#define HOOKSELF_MAX_SYSCALL_RULES 128U
#define HOOKSELF_MAX_VIRTUAL_FILES 64U
#define HOOKSELF_MAX_VIRTUAL_FILE_SIZE 1048576U
#define HOOKSELF_MAX_EVENT_CAPACITY 1024U
#define HOOKSELF_SYSCALL_LIMIT 1024U
#define HOOKSELF_LOG_MESSAGE_CAPACITY 4096U
#define HOOKSELF_PTRACE_CAPABILITIES_VERSION 2U
#define HOOKSELF_BUILTIN_RULE_ID_MIN 0xffff0000U
#define HOOKSELF_BUILTIN_RULE_PROTECTED_FD 0xffff0001U
#define HOOKSELF_BUILTIN_RULE_PTRACE_TRACEME 0xffff0002U
#define HOOKSELF_BUILTIN_RULE_DUMPABLE_VIEW 0xffff0003U
#define HOOKSELF_BUILTIN_RULE_PTRACER_VIEW 0xffff0004U
#define HOOKSELF_BUILTIN_RULE_PROC_STATUS_VIEW 0xffff0005U
#define HOOKSELF_BUILTIN_RULE_NESTED_PTRACE 0xffff0006U

typedef struct HookselfRuntime HookselfRuntime;

typedef enum HookselfResult {
    HOOKSELF_OK = 0,
    HOOKSELF_E_INVALID_ARGUMENT = -10001,
    HOOKSELF_E_ABI_MISMATCH = -10002,
    HOOKSELF_E_INVALID_STATE = -10003,
    HOOKSELF_E_BUSY = -10004,
    HOOKSELF_E_NO_MEMORY = -10005,
    HOOKSELF_E_UNSUPPORTED = -10006,
    HOOKSELF_E_NOT_IMPLEMENTED = -10007,
    HOOKSELF_E_CAPACITY = -10008,
    HOOKSELF_E_INTERNAL = -10009,
} HookselfResult;

typedef enum HookselfBackend {
    HOOKSELF_BACKEND_FORK_RAW = 1,
    HOOKSELF_BACKEND_SPAWN_EXEC = 2,
    HOOKSELF_BACKEND_APP_SERVICE = 3,
} HookselfBackend;

typedef enum HookselfFailureMode {
    HOOKSELF_FAILURE_FULL_PTRACE_FAIL_OPEN = 1,
    HOOKSELF_FAILURE_FAIL_CLOSED = 2,
} HookselfFailureMode;

typedef enum HookselfRuntimeState {
    HOOKSELF_STATE_IDLE = 0,
    HOOKSELF_STATE_CONFIGURED = 1,
    HOOKSELF_STATE_STARTING = 2,
    HOOKSELF_STATE_RUNNING_FULL_PTRACE = 3,
    HOOKSELF_STATE_INSTALLING_FILTER = 4,
    HOOKSELF_STATE_RUNNING_SELECTIVE = 5,
    HOOKSELF_STATE_STOPPING = 6,
    HOOKSELF_STATE_STOPPED = 7,
    HOOKSELF_STATE_FATAL = 8,
} HookselfRuntimeState;

typedef enum HookselfFatalStage {
    HOOKSELF_FATAL_NONE = 0,
    HOOKSELF_FATAL_IDENTITY = 1,
    HOOKSELF_FATAL_SHARED_ABI = 2,
    HOOKSELF_FATAL_WORKSPACE = 3,
    HOOKSELF_FATAL_TASK_ENUMERATION = 4,
    HOOKSELF_FATAL_TASK_TABLE_FULL = 5,
    HOOKSELF_FATAL_SEIZE = 6,
    HOOKSELF_FATAL_INTERRUPT = 7,
    HOOKSELF_FATAL_WAIT = 8,
    HOOKSELF_FATAL_COVERAGE = 9,
    HOOKSELF_FATAL_REGISTERS = 10,
    HOOKSELF_FATAL_RESUME = 11,
    HOOKSELF_FATAL_EVENT_MESSAGE = 12,
    HOOKSELF_FATAL_DETACH = 13,
    HOOKSELF_FATAL_CONTROL = 14,
    HOOKSELF_FATAL_SCRATCH_MAPPING = 15,
    HOOKSELF_FATAL_EXEC_MIGRATION = 16,
    HOOKSELF_FATAL_TASK_IDENTITY = 17,
    HOOKSELF_FATAL_SYSCALL = 18,
    HOOKSELF_FATAL_POLL = 19,
    HOOKSELF_FATAL_SECCOMP_PLAN = 20,
    HOOKSELF_FATAL_SECCOMP_INSTALL = 21,
    HOOKSELF_FATAL_SECCOMP_COMMIT = 22,
    HOOKSELF_FATAL_SECCOMP_PROTOCOL = 23,
} HookselfFatalStage;

typedef enum HookselfLogLevel {
    HOOKSELF_LOG_OFF = 0,
    HOOKSELF_LOG_ERROR = 1,
    HOOKSELF_LOG_WARN = 2,
    HOOKSELF_LOG_INFO = 3,
    HOOKSELF_LOG_DEBUG = 4,
    HOOKSELF_LOG_TRACE = 5,
} HookselfLogLevel;

enum HookselfConfigFlags {
    HOOKSELF_CONFIG_OBSERVE_ALL = 1U << 0,
    HOOKSELF_CONFIG_CAPTURE_PATHS = 1U << 1,
    HOOKSELF_CONFIG_CAPTURE_ARGUMENTS = 1U << 2,
    HOOKSELF_CONFIG_CAPTURE_RESULTS = 1U << 3,
    HOOKSELF_CONFIG_TRACE_DESCENDANTS = 1U << 4,
    HOOKSELF_CONFIG_ENABLE_PATH_REDIRECT = 1U << 5,
    HOOKSELF_CONFIG_ENABLE_VIRTUAL_FILES = 1U << 6,
    HOOKSELF_CONFIG_ENABLE_PTRACE_VIEW = 1U << 7,
    HOOKSELF_CONFIG_ENABLE_SELECTIVE_SECCOMP = 1U << 8,
    HOOKSELF_CONFIG_ENABLE_PROC_VIRTUAL_VIEW = 1U << 9,
    /* Requires ENABLE_PTRACE_VIEW, TRACE_DESCENDANTS, FAIL_CLOSED and the
     * full-ptrace runtime (ENABLE_SELECTIVE_SECCOMP must be clear). */
    HOOKSELF_CONFIG_ENABLE_NESTED_PTRACE = 1U << 10,
};

enum HookselfPtraceFeature {
    HOOKSELF_PTRACE_FEATURE_TRACEME_VIEW = 1U << 0,
    HOOKSELF_PTRACE_FEATURE_DUMPABLE_PTRACER_VIEW = 1U << 1,
    HOOKSELF_PTRACE_FEATURE_PROC_STATUS_VIEW = 1U << 2,
    HOOKSELF_PTRACE_FEATURE_DESCENDANT_TGID_STATE = 1U << 3,
    HOOKSELF_PTRACE_FEATURE_ATTACH_SEIZE = 1U << 4,
    HOOKSELF_PTRACE_FEATURE_RESUME_CONTROL = 1U << 5,
    HOOKSELF_PTRACE_FEATURE_WAIT_EMULATION = 1U << 6,
    HOOKSELF_PTRACE_FEATURE_SIGNAL_STATE = 1U << 7,
    HOOKSELF_PTRACE_FEATURE_MEMORY_ACCESS = 1U << 8,
    HOOKSELF_PTRACE_FEATURE_REGSET = 1U << 9,
    HOOKSELF_PTRACE_FEATURE_SYSCALL_INFO = 1U << 10,
    /* Direct-child leader TRACEME -> exec-stop bridge. This does not imply
     * that every logical engine feature is resident-backed. */
    HOOKSELF_PTRACE_FEATURE_NESTED_TRACEME_EXEC = 1U << 11,
};

/* runtime_features are available through the resident runtime today.
 * engine_features are implemented by the compiled logical engine; callers
 * must not treat them as resident features unless runtime_features also
 * contains the corresponding bit. */
typedef struct HookselfPtraceCapabilities {
    uint32_t struct_size;
    uint32_t version;
    uint64_t runtime_features;
    uint64_t engine_features;
    uint32_t max_tasks;
    uint32_t max_relations;
    uint32_t max_pending_waits;
    uint32_t per_tracee_event_capacity;
    uint32_t reserved[4];
} HookselfPtraceCapabilities;

typedef enum HookselfPathAction {
    HOOKSELF_PATH_PASS = 0,
    HOOKSELF_PATH_REDIRECT = 1,
    HOOKSELF_PATH_DENY = 2,
    HOOKSELF_PATH_VIRTUAL_FILE = 3,
} HookselfPathAction;

enum HookselfPathOperation {
    HOOKSELF_PATH_OP_LOOKUP = 1U << 0,
    HOOKSELF_PATH_OP_READ = 1U << 1,
    HOOKSELF_PATH_OP_WRITE = 1U << 2,
    HOOKSELF_PATH_OP_CREATE = 1U << 3,
    HOOKSELF_PATH_OP_DELETE = 1U << 4,
    HOOKSELF_PATH_OP_RENAME = 1U << 5,
    HOOKSELF_PATH_OP_METADATA = 1U << 6,
    HOOKSELF_PATH_OP_EXECUTE = 1U << 7,
    HOOKSELF_PATH_OP_ALL = 0xffU,
};

enum HookselfPathRuleFlags {
    HOOKSELF_PATH_RULE_FOLLOW_FINAL = 1U << 0,
    HOOKSELF_PATH_RULE_READ_ONLY = 1U << 1,
    HOOKSELF_PATH_RULE_REVERSE_VISIBLE = 1U << 2,
};

typedef struct HookselfPathRule {
    uint32_t struct_size;
    uint32_t rule_id;
    int32_t priority;
    int32_t action;
    uint32_t operation_mask;
    uint32_t flags;
    int32_t deny_errno;
    uint32_t reserved;
    char guest_prefix[HOOKSELF_PATH_CAPACITY];
    char host_prefix[HOOKSELF_PATH_CAPACITY];
} HookselfPathRule;

typedef enum HookselfSyscallAction {
    HOOKSELF_SYSCALL_PASS = 0,
    HOOKSELF_SYSCALL_OBSERVE = 1,
    HOOKSELF_SYSCALL_DENY = 2,
    HOOKSELF_SYSCALL_REPLACE_RESULT = 3,
    HOOKSELF_SYSCALL_REPLACE_NUMBER = 4,
    HOOKSELF_SYSCALL_REPLACE_ARGUMENT = 5,
} HookselfSyscallAction;

enum HookselfSyscallPhase {
    HOOKSELF_SYSCALL_PHASE_ENTRY = 1U << 0,
    HOOKSELF_SYSCALL_PHASE_EXIT = 1U << 1,
    HOOKSELF_SYSCALL_PHASE_BOTH = 3U,
};

typedef struct HookselfSyscallRule {
    uint32_t struct_size;
    uint32_t rule_id;
    int32_t syscall_number;
    int32_t action;
    uint32_t phase_mask;
    uint32_t argument_index;
    uint64_t argument_match_mask;
    uint64_t argument_match_value;
    uint64_t replacement_value;
    int32_t replacement_syscall_number;
    int32_t deny_errno;
    uint32_t flags;
    uint32_t reserved;
} HookselfSyscallRule;

typedef enum HookselfVirtualFileProvider {
    HOOKSELF_VFILE_STATIC = 0,
    HOOKSELF_VFILE_DYNAMIC_SNAPSHOT = 1,
    HOOKSELF_VFILE_PROC_STATUS = 2,
    HOOKSELF_VFILE_PROC_MAPS = 3,
    HOOKSELF_VFILE_SELINUX_CONTEXT = 4,
} HookselfVirtualFileProvider;

enum HookselfVirtualFileFlags {
    HOOKSELF_VFILE_F_HIDE_INTERNAL_MAPPINGS = 1U << 0,
};

typedef struct HookselfVirtualFile {
    uint32_t struct_size;
    uint32_t file_id;
    int32_t provider;
    uint32_t mode;
    uint32_t flags;
    uint32_t initial_content_size;
    const uint8_t* initial_content;
    char guest_path[HOOKSELF_PATH_CAPACITY];
} HookselfVirtualFile;

typedef enum HookselfEventKind {
    HOOKSELF_EVENT_LIFECYCLE = 1,
    HOOKSELF_EVENT_SYSCALL = 2,
    HOOKSELF_EVENT_PATH = 3,
    HOOKSELF_EVENT_SIGNAL = 4,
    HOOKSELF_EVENT_PROCESS = 5,
    HOOKSELF_EVENT_INTERNAL_ERROR = 6,
} HookselfEventKind;

enum HookselfEventFlags {
    HOOKSELF_EVENT_F_PATH_CAPTURE_FAILED = 1U << 0,
    HOOKSELF_EVENT_F_PATH_TRUNCATED = 1U << 1,
    HOOKSELF_EVENT_F_SYSCALL_INFO_FALLBACK = 1U << 2,
    HOOKSELF_EVENT_F_NEW_TASK = 1U << 3,
    HOOKSELF_EVENT_F_EXEC = 1U << 4,
    HOOKSELF_EVENT_F_EXIT = 1U << 5,
    HOOKSELF_EVENT_F_PATH_RESOLVED_RELATIVE = 1U << 6,
    HOOKSELF_EVENT_F_SYSCALL_RESTART = 1U << 7,
    HOOKSELF_EVENT_F_PATH_ARGUMENT_SHIFT = 8,
    HOOKSELF_EVENT_F_PATH_ARGUMENT_MASK = 7U << HOOKSELF_EVENT_F_PATH_ARGUMENT_SHIFT,
    HOOKSELF_EVENT_F_EXEC_RECOVERED = 1U << 11,
    HOOKSELF_EVENT_F_PTRACE_VIEW = 1U << 12,
    HOOKSELF_EVENT_F_PROC_STATUS_VIEW = 1U << 13,
    HOOKSELF_EVENT_F_NESTED_PTRACE = 1U << 14,
};

typedef struct HookselfEvent {
    uint32_t struct_size;
    uint32_t kind;
    uint64_t sequence;
    int64_t monotonic_time_ns;
    int32_t tgid;
    int32_t tid;
    int32_t syscall_number;
    uint32_t phase;
    int32_t action;
    int32_t error;
    int64_t result;
    uint64_t arguments[6];
    uint32_t rule_id;
    uint32_t flags;
    char path[HOOKSELF_EVENT_PATH_CAPACITY];
    char translated_path[HOOKSELF_EVENT_PATH_CAPACITY];
} HookselfEvent;

/* event and message remain valid only until this synchronous callback returns. */
typedef void (*HookselfLogSink)(int32_t level, const HookselfEvent* event,
                                const char* message, void* user_data);

typedef struct HookselfConfig {
    uint32_t struct_size;
    uint32_t abi_version;
    int32_t backend;
    int32_t failure_mode;
    int32_t log_level;
    uint32_t flags;
    uint32_t event_capacity;
    uint32_t path_rule_count;
    const HookselfPathRule* path_rules;
    uint32_t syscall_rule_count;
    const HookselfSyscallRule* syscall_rules;
    uint32_t virtual_file_count;
    const HookselfVirtualFile* virtual_files;
    /* Absolute, canonical app-private directory supplied by the caller.
     * When virtual_file_count is nonzero, HookSelf creates one private
     * runtime subdirectory below this root and removes only that subdirectory
     * during teardown. */
    char virtual_backing_dir[HOOKSELF_PATH_CAPACITY];
    uint32_t reserved[8];
} HookselfConfig;

typedef struct HookselfStats {
    uint32_t struct_size;
    uint32_t state;
    uint64_t emitted_events;
    uint64_t dropped_events;
    uint64_t observed_syscalls;
    uint64_t redirected_paths;
    uint64_t virtual_file_opens;
    uint64_t internal_errors;
    uint64_t protected_fd_blocks;
    uint64_t internal_fd_operations;
    uint64_t ptrace_view_operations;
    uint64_t proc_status_patches;
    uint32_t tracked_tasks;
    int32_t fatal_code;
    int32_t fatal_errno;
    int32_t fatal_tid;
    uint32_t reserved[4];
} HookselfStats;

/* Public hookself APIs use locks and allocation and are not async-signal-safe.
 * Do not call them from a signal handler. */
HOOKSELF_API void hookself_default_config(HookselfConfig* config);
HOOKSELF_API int32_t hookself_validate_config(const HookselfConfig* config);
HOOKSELF_API const char* hookself_result_string(int32_t result);
HOOKSELF_API int32_t hookself_get_ptrace_capabilities(
        HookselfPtraceCapabilities* capabilities);

HOOKSELF_API int32_t hookself_create(const HookselfConfig* config,
                                     HookselfRuntime** runtime);
/*
 * In-flight API calls are allowed to finish. A destroy requested by a log sink
 * is deferred until the outer drain releases its locks; that drain returns
 * HOOKSELF_E_INVALID_STATE. Do not start new calls after requesting destroy,
 * and use only one destroy caller for a runtime. A committed selective filter
 * is process-lifetime: destroy first enters pass-through and leaves the minimal
 * tracer resident until process exit.
 */
HOOKSELF_API void hookself_destroy(HookselfRuntime* runtime);
HOOKSELF_API int32_t hookself_start(HookselfRuntime* runtime);
/* Selective stop quiesces policy work but keeps a pass-through tracer attached. */
HOOKSELF_API int32_t hookself_stop(HookselfRuntime* runtime);
HOOKSELF_API int32_t hookself_get_state(const HookselfRuntime* runtime,
                                        int32_t* state);
HOOKSELF_API int32_t hookself_get_stats(const HookselfRuntime* runtime,
                                        HookselfStats* stats);
HOOKSELF_API size_t hookself_read_events(HookselfRuntime* runtime,
                                         HookselfEvent* events,
                                         size_t capacity);
HOOKSELF_API const char* hookself_syscall_name(int32_t syscall_number);
HOOKSELF_API int32_t hookself_event_log_level(const HookselfEvent* event);
HOOKSELF_API int32_t hookself_format_event(const HookselfEvent* event,
                                           char* message, size_t capacity,
                                           size_t* required_size);
HOOKSELF_API int32_t hookself_set_log_sink(HookselfRuntime* runtime,
                                           HookselfLogSink sink,
                                           void* user_data);
HOOKSELF_API int32_t hookself_drain_logs(HookselfRuntime* runtime,
                                         size_t max_events,
                                         size_t* consumed_events,
                                         size_t* emitted_logs);
HOOKSELF_API int32_t hookself_publish_virtual_file(
        HookselfRuntime* runtime, uint32_t file_id, const uint8_t* content,
        size_t content_size);
HOOKSELF_API int32_t hookself_refresh_virtual_file(HookselfRuntime* runtime,
                                                   uint32_t file_id);

#ifdef __cplusplus
}
#endif

#endif
