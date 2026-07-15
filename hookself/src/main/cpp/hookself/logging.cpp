#include "hookself/public_api.h"

#include <asm/unistd.h>

#include <cstddef>
#include <cstdint>

namespace {

class TextBuilder {
  public:
    TextBuilder(char* output, size_t capacity)
        : output_(output), capacity_(capacity), required_(0) {
        if (output_ != nullptr && capacity_ != 0) {
            output_[0] = '\0';
        }
    }

    void Append(char value) {
        if (output_ != nullptr && required_ + 1U < capacity_) {
            output_[required_] = value;
        }
        ++required_;
    }

    void Append(const char* value) {
        if (value == nullptr) {
            return;
        }
        for (size_t i = 0; value[i] != '\0'; ++i) {
            Append(value[i]);
        }
    }

    void AppendUnsigned(uint64_t value) {
        char reversed[32]{};
        size_t digits = 0;
        do {
            reversed[digits++] = static_cast<char>('0' + value % 10U);
            value /= 10U;
        } while (value != 0);
        while (digits != 0) {
            Append(reversed[--digits]);
        }
    }

    void AppendSigned(int64_t value) {
        if (value < 0) {
            Append('-');
            AppendUnsigned(0U - static_cast<uint64_t>(value));
            return;
        }
        AppendUnsigned(static_cast<uint64_t>(value));
    }

    void AppendHex(uint64_t value) {
        constexpr char kDigits[] = "0123456789abcdef";
        char reversed[16]{};
        size_t digits = 0;
        do {
            reversed[digits++] = kDigits[value & 0xfU];
            value >>= 4U;
        } while (value != 0);
        Append("0x");
        while (digits != 0) {
            Append(reversed[--digits]);
        }
    }

    void AppendEscaped(const char* value, size_t capacity) {
        constexpr char kHex[] = "0123456789abcdef";
        if (value == nullptr) {
            return;
        }
        for (size_t i = 0; i < capacity && value[i] != '\0'; ++i) {
            const uint8_t byte = static_cast<uint8_t>(value[i]);
            switch (byte) {
                case '\\': Append("\\\\"); break;
                case '"': Append("\\\""); break;
                case '\n': Append("\\n"); break;
                case '\r': Append("\\r"); break;
                case '\t': Append("\\t"); break;
                default:
                    if (byte >= 0x20U && byte <= 0x7eU) {
                        Append(static_cast<char>(byte));
                    } else {
                        Append("\\x");
                        Append(kHex[(byte >> 4U) & 0xfU]);
                        Append(kHex[byte & 0xfU]);
                    }
                    break;
            }
        }
    }

    size_t Finish() {
        if (output_ != nullptr && capacity_ != 0) {
            const size_t terminator =
                    required_ < capacity_ ? required_ : capacity_ - 1U;
            output_[terminator] = '\0';
        }
        return required_;
    }

  private:
    char* output_;
    size_t capacity_;
    size_t required_;
};

const char* LogLevelName(int32_t level) {
    switch (level) {
        case HOOKSELF_LOG_ERROR: return "ERROR";
        case HOOKSELF_LOG_WARN: return "WARN";
        case HOOKSELF_LOG_INFO: return "INFO";
        case HOOKSELF_LOG_DEBUG: return "DEBUG";
        case HOOKSELF_LOG_TRACE: return "TRACE";
        default: return "OFF";
    }
}

const char* EventKindName(uint32_t kind) {
    switch (kind) {
        case HOOKSELF_EVENT_LIFECYCLE: return "LIFECYCLE";
        case HOOKSELF_EVENT_SYSCALL: return "SYSCALL";
        case HOOKSELF_EVENT_PATH: return "PATH";
        case HOOKSELF_EVENT_SIGNAL: return "SIGNAL";
        case HOOKSELF_EVENT_PROCESS: return "PROCESS";
        case HOOKSELF_EVENT_INTERNAL_ERROR: return "INTERNAL_ERROR";
        default: return "UNKNOWN";
    }
}

const char* PhaseName(uint32_t phase) {
    switch (phase) {
        case HOOKSELF_SYSCALL_PHASE_ENTRY: return "ENTRY";
        case HOOKSELF_SYSCALL_PHASE_EXIT: return "EXIT";
        case HOOKSELF_SYSCALL_PHASE_BOTH: return "BOTH";
        default: return "NONE";
    }
}

const char* SyscallActionName(int32_t action) {
    switch (action) {
        case HOOKSELF_SYSCALL_PASS: return "PASS";
        case HOOKSELF_SYSCALL_OBSERVE: return "OBSERVE";
        case HOOKSELF_SYSCALL_DENY: return "DENY";
        case HOOKSELF_SYSCALL_REPLACE_RESULT: return "REPLACE_RESULT";
        case HOOKSELF_SYSCALL_REPLACE_NUMBER: return "REPLACE_NUMBER";
        case HOOKSELF_SYSCALL_REPLACE_ARGUMENT: return "REPLACE_ARGUMENT";
        default: return "UNKNOWN";
    }
}

const char* PathActionName(int32_t action) {
    switch (action) {
        case HOOKSELF_PATH_PASS: return "PASS";
        case HOOKSELF_PATH_REDIRECT: return "REDIRECT";
        case HOOKSELF_PATH_DENY: return "DENY";
        case HOOKSELF_PATH_VIRTUAL_FILE: return "VIRTUAL_FILE";
        default: return "UNKNOWN";
    }
}

const char* RuntimeStateName(int32_t state) {
    switch (state) {
        case HOOKSELF_STATE_IDLE: return "IDLE";
        case HOOKSELF_STATE_CONFIGURED: return "CONFIGURED";
        case HOOKSELF_STATE_STARTING: return "STARTING";
        case HOOKSELF_STATE_RUNNING_FULL_PTRACE: return "RUNNING_FULL_PTRACE";
        case HOOKSELF_STATE_INSTALLING_FILTER: return "INSTALLING_FILTER";
        case HOOKSELF_STATE_RUNNING_SELECTIVE: return "RUNNING_SELECTIVE";
        case HOOKSELF_STATE_STOPPING: return "STOPPING";
        case HOOKSELF_STATE_STOPPED: return "STOPPED";
        case HOOKSELF_STATE_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

const char* EventActionName(const HookselfEvent& event) {
    if (event.kind == HOOKSELF_EVENT_SYSCALL) {
        return SyscallActionName(event.action);
    }
    if (event.kind == HOOKSELF_EVENT_PATH) {
        return PathActionName(event.action);
    }
    if (event.kind == HOOKSELF_EVENT_LIFECYCLE) {
        return RuntimeStateName(event.action);
    }
    return "VALUE";
}

bool EventValid(const HookselfEvent* event) {
    return event != nullptr && event->struct_size >= sizeof(HookselfEvent);
}

void AppendFormattedEvent(TextBuilder* builder, const HookselfEvent& event,
                          bool include_paths) {
    const int32_t level = hookself_event_log_level(&event);
    builder->Append("level=");
    builder->Append(LogLevelName(level));
    builder->Append(" kind=");
    builder->Append(EventKindName(event.kind));
    builder->Append(" seq=");
    builder->AppendUnsigned(event.sequence);
    builder->Append(" time_ns=");
    builder->AppendSigned(event.monotonic_time_ns);
    builder->Append(" tgid=");
    builder->AppendSigned(event.tgid);
    builder->Append(" tid=");
    builder->AppendSigned(event.tid);
    builder->Append(" syscall=");
    builder->Append(hookself_syscall_name(event.syscall_number));
    builder->Append('(');
    builder->AppendSigned(event.syscall_number);
    builder->Append(") phase=");
    builder->Append(PhaseName(event.phase));
    builder->Append(" action=");
    builder->Append(EventActionName(event));
    builder->Append('(');
    builder->AppendSigned(event.action);
    builder->Append(") result=");
    builder->AppendSigned(event.result);
    builder->Append(" error=");
    builder->AppendSigned(event.error);
    builder->Append(" rule=");
    builder->AppendUnsigned(event.rule_id);
    builder->Append(" flags=");
    builder->AppendHex(event.flags);
    if (event.kind == HOOKSELF_EVENT_SYSCALL) {
        builder->Append(" args=[");
        for (size_t i = 0; i < 6; ++i) {
            if (i != 0) {
                builder->Append(',');
            }
            builder->AppendHex(event.arguments[i]);
        }
        builder->Append(']');
    }
    if (include_paths) {
        if (event.path[0] != '\0') {
            builder->Append(" path=\"");
            builder->AppendEscaped(event.path, sizeof(event.path));
            builder->Append('"');
        }
        if (event.translated_path[0] != '\0') {
            builder->Append(" translated=\"");
            builder->AppendEscaped(event.translated_path,
                                   sizeof(event.translated_path));
            builder->Append('"');
        }
        return;
    }
    if (event.path[0] != '\0') {
        builder->Append(" path_truncated=true");
    }
    if (event.translated_path[0] != '\0') {
        builder->Append(" translated_path_truncated=true");
    }
}

}  // namespace

extern "C" const char* hookself_syscall_name(int32_t syscall_number) {
    switch (syscall_number) {
#ifdef __NR_read
        case __NR_read: return "read";
#endif
#ifdef __NR_write
        case __NR_write: return "write";
#endif
#ifdef __NR_readv
        case __NR_readv: return "readv";
#endif
#ifdef __NR_writev
        case __NR_writev: return "writev";
#endif
#ifdef __NR_pread64
        case __NR_pread64: return "pread64";
#endif
#ifdef __NR_pwrite64
        case __NR_pwrite64: return "pwrite64";
#endif
#ifdef __NR_preadv
        case __NR_preadv: return "preadv";
#endif
#ifdef __NR_pwritev
        case __NR_pwritev: return "pwritev";
#endif
#ifdef __NR_preadv2
        case __NR_preadv2: return "preadv2";
#endif
#ifdef __NR_pwritev2
        case __NR_pwritev2: return "pwritev2";
#endif
#ifdef __NR_openat
        case __NR_openat: return "openat";
#endif
#ifdef __NR_openat2
        case __NR_openat2: return "openat2";
#endif
#ifdef __NR_close
        case __NR_close: return "close";
#endif
#ifdef __NR_close_range
        case __NR_close_range: return "close_range";
#endif
#ifdef __NR_lseek
        case __NR_lseek: return "lseek";
#endif
#ifdef __NR_ftruncate
        case __NR_ftruncate: return "ftruncate";
#endif
#ifdef __NR_fsync
        case __NR_fsync: return "fsync";
#endif
#ifdef __NR_fdatasync
        case __NR_fdatasync: return "fdatasync";
#endif
#ifdef __NR_syncfs
        case __NR_syncfs: return "syncfs";
#endif
#ifdef __NR_sendfile
        case __NR_sendfile: return "sendfile";
#endif
#ifdef __NR_copy_file_range
        case __NR_copy_file_range: return "copy_file_range";
#endif
#ifdef __NR_splice
        case __NR_splice: return "splice";
#endif
#ifdef __NR_tee
        case __NR_tee: return "tee";
#endif
#ifdef __NR_vmsplice
        case __NR_vmsplice: return "vmsplice";
#endif
#ifdef __NR_fstat
        case __NR_fstat: return "fstat";
#endif
#ifdef __NR_newfstatat
        case __NR_newfstatat: return "newfstatat";
#endif
#ifdef __NR_statx
        case __NR_statx: return "statx";
#endif
#ifdef __NR_faccessat
        case __NR_faccessat: return "faccessat";
#endif
#ifdef __NR_faccessat2
        case __NR_faccessat2: return "faccessat2";
#endif
#ifdef __NR_readlinkat
        case __NR_readlinkat: return "readlinkat";
#endif
#ifdef __NR_unlinkat
        case __NR_unlinkat: return "unlinkat";
#endif
#ifdef __NR_mkdirat
        case __NR_mkdirat: return "mkdirat";
#endif
#ifdef __NR_mknodat
        case __NR_mknodat: return "mknodat";
#endif
#ifdef __NR_fchmodat
        case __NR_fchmodat: return "fchmodat";
#endif
#ifdef __NR_fchownat
        case __NR_fchownat: return "fchownat";
#endif
#ifdef __NR_renameat
        case __NR_renameat: return "renameat";
#endif
#ifdef __NR_renameat2
        case __NR_renameat2: return "renameat2";
#endif
#ifdef __NR_linkat
        case __NR_linkat: return "linkat";
#endif
#ifdef __NR_symlinkat
        case __NR_symlinkat: return "symlinkat";
#endif
#ifdef __NR_getdents64
        case __NR_getdents64: return "getdents64";
#endif
#ifdef __NR_getxattr
        case __NR_getxattr: return "getxattr";
#endif
#ifdef __NR_lgetxattr
        case __NR_lgetxattr: return "lgetxattr";
#endif
#ifdef __NR_fgetxattr
        case __NR_fgetxattr: return "fgetxattr";
#endif
#ifdef __NR_setxattr
        case __NR_setxattr: return "setxattr";
#endif
#ifdef __NR_lsetxattr
        case __NR_lsetxattr: return "lsetxattr";
#endif
#ifdef __NR_fsetxattr
        case __NR_fsetxattr: return "fsetxattr";
#endif
#ifdef __NR_listxattr
        case __NR_listxattr: return "listxattr";
#endif
#ifdef __NR_llistxattr
        case __NR_llistxattr: return "llistxattr";
#endif
#ifdef __NR_flistxattr
        case __NR_flistxattr: return "flistxattr";
#endif
#ifdef __NR_removexattr
        case __NR_removexattr: return "removexattr";
#endif
#ifdef __NR_mount
        case __NR_mount: return "mount";
#endif
#ifdef __NR_umount2
        case __NR_umount2: return "umount2";
#endif
#ifdef __NR_pivot_root
        case __NR_pivot_root: return "pivot_root";
#endif
#ifdef __NR_chroot
        case __NR_chroot: return "chroot";
#endif
#ifdef __NR_open_tree
        case __NR_open_tree: return "open_tree";
#endif
#ifdef __NR_move_mount
        case __NR_move_mount: return "move_mount";
#endif
#ifdef __NR_mount_setattr
        case __NR_mount_setattr: return "mount_setattr";
#endif
#ifdef __NR_chdir
        case __NR_chdir: return "chdir";
#endif
#ifdef __NR_fchdir
        case __NR_fchdir: return "fchdir";
#endif
#ifdef __NR_execve
        case __NR_execve: return "execve";
#endif
#ifdef __NR_execveat
        case __NR_execveat: return "execveat";
#endif
#ifdef __NR_clone
        case __NR_clone: return "clone";
#endif
#ifdef __NR_clone3
        case __NR_clone3: return "clone3";
#endif
#ifdef __NR_wait4
        case __NR_wait4: return "wait4";
#endif
#ifdef __NR_set_tid_address
        case __NR_set_tid_address: return "set_tid_address";
#endif
#ifdef __NR_set_robust_list
        case __NR_set_robust_list: return "set_robust_list";
#endif
#ifdef __NR_get_robust_list
        case __NR_get_robust_list: return "get_robust_list";
#endif
#ifdef __NR_rseq
        case __NR_rseq: return "rseq";
#endif
#ifdef __NR_exit
        case __NR_exit: return "exit";
#endif
#ifdef __NR_exit_group
        case __NR_exit_group: return "exit_group";
#endif
#ifdef __NR_getpid
        case __NR_getpid: return "getpid";
#endif
#ifdef __NR_gettid
        case __NR_gettid: return "gettid";
#endif
#ifdef __NR_getppid
        case __NR_getppid: return "getppid";
#endif
#ifdef __NR_getuid
        case __NR_getuid: return "getuid";
#endif
#ifdef __NR_geteuid
        case __NR_geteuid: return "geteuid";
#endif
#ifdef __NR_getgid
        case __NR_getgid: return "getgid";
#endif
#ifdef __NR_getegid
        case __NR_getegid: return "getegid";
#endif
#ifdef __NR_tgkill
        case __NR_tgkill: return "tgkill";
#endif
#ifdef __NR_kill
        case __NR_kill: return "kill";
#endif
#ifdef __NR_ptrace
        case __NR_ptrace: return "ptrace";
#endif
#ifdef __NR_prctl
        case __NR_prctl: return "prctl";
#endif
#ifdef __NR_seccomp
        case __NR_seccomp: return "seccomp";
#endif
#ifdef __NR_futex
        case __NR_futex: return "futex";
#endif
#ifdef __NR_futex_waitv
        case __NR_futex_waitv: return "futex_waitv";
#endif
#ifdef __NR_rt_sigaction
        case __NR_rt_sigaction: return "rt_sigaction";
#endif
#ifdef __NR_rt_sigprocmask
        case __NR_rt_sigprocmask: return "rt_sigprocmask";
#endif
#ifdef __NR_rt_sigreturn
        case __NR_rt_sigreturn: return "rt_sigreturn";
#endif
#ifdef __NR_sigaltstack
        case __NR_sigaltstack: return "sigaltstack";
#endif
#ifdef __NR_mmap
        case __NR_mmap: return "mmap";
#endif
#ifdef __NR_mprotect
        case __NR_mprotect: return "mprotect";
#endif
#ifdef __NR_munmap
        case __NR_munmap: return "munmap";
#endif
#ifdef __NR_madvise
        case __NR_madvise: return "madvise";
#endif
#ifdef __NR_mremap
        case __NR_mremap: return "mremap";
#endif
#ifdef __NR_memfd_create
        case __NR_memfd_create: return "memfd_create";
#endif
#ifdef __NR_brk
        case __NR_brk: return "brk";
#endif
#ifdef __NR_ioctl
        case __NR_ioctl: return "ioctl";
#endif
#ifdef __NR_fcntl
        case __NR_fcntl: return "fcntl";
#endif
#ifdef __NR_dup
        case __NR_dup: return "dup";
#endif
#ifdef __NR_dup3
        case __NR_dup3: return "dup3";
#endif
#ifdef __NR_pipe2
        case __NR_pipe2: return "pipe2";
#endif
#ifdef __NR_eventfd2
        case __NR_eventfd2: return "eventfd2";
#endif
#ifdef __NR_epoll_create1
        case __NR_epoll_create1: return "epoll_create1";
#endif
#ifdef __NR_epoll_ctl
        case __NR_epoll_ctl: return "epoll_ctl";
#endif
#ifdef __NR_epoll_pwait
        case __NR_epoll_pwait: return "epoll_pwait";
#endif
#ifdef __NR_epoll_pwait2
        case __NR_epoll_pwait2: return "epoll_pwait2";
#endif
#ifdef __NR_timerfd_create
        case __NR_timerfd_create: return "timerfd_create";
#endif
#ifdef __NR_timerfd_settime
        case __NR_timerfd_settime: return "timerfd_settime";
#endif
#ifdef __NR_timerfd_gettime
        case __NR_timerfd_gettime: return "timerfd_gettime";
#endif
#ifdef __NR_socket
        case __NR_socket: return "socket";
#endif
#ifdef __NR_connect
        case __NR_connect: return "connect";
#endif
#ifdef __NR_bind
        case __NR_bind: return "bind";
#endif
#ifdef __NR_listen
        case __NR_listen: return "listen";
#endif
#ifdef __NR_accept
        case __NR_accept: return "accept";
#endif
#ifdef __NR_accept4
        case __NR_accept4: return "accept4";
#endif
#ifdef __NR_socketpair
        case __NR_socketpair: return "socketpair";
#endif
#ifdef __NR_shutdown
        case __NR_shutdown: return "shutdown";
#endif
#ifdef __NR_getsockname
        case __NR_getsockname: return "getsockname";
#endif
#ifdef __NR_getpeername
        case __NR_getpeername: return "getpeername";
#endif
#ifdef __NR_setsockopt
        case __NR_setsockopt: return "setsockopt";
#endif
#ifdef __NR_getsockopt
        case __NR_getsockopt: return "getsockopt";
#endif
#ifdef __NR_sendto
        case __NR_sendto: return "sendto";
#endif
#ifdef __NR_recvfrom
        case __NR_recvfrom: return "recvfrom";
#endif
#ifdef __NR_sendmsg
        case __NR_sendmsg: return "sendmsg";
#endif
#ifdef __NR_recvmsg
        case __NR_recvmsg: return "recvmsg";
#endif
#ifdef __NR_sendmmsg
        case __NR_sendmmsg: return "sendmmsg";
#endif
#ifdef __NR_recvmmsg
        case __NR_recvmmsg: return "recvmmsg";
#endif
#ifdef __NR_clock_gettime
        case __NR_clock_gettime: return "clock_gettime";
#endif
#ifdef __NR_clock_nanosleep
        case __NR_clock_nanosleep: return "clock_nanosleep";
#endif
#ifdef __NR_nanosleep
        case __NR_nanosleep: return "nanosleep";
#endif
#ifdef __NR_gettimeofday
        case __NR_gettimeofday: return "gettimeofday";
#endif
#ifdef __NR_getrandom
        case __NR_getrandom: return "getrandom";
#endif
#ifdef __NR_prlimit64
        case __NR_prlimit64: return "prlimit64";
#endif
#ifdef __NR_sched_yield
        case __NR_sched_yield: return "sched_yield";
#endif
#ifdef __NR_sched_getaffinity
        case __NR_sched_getaffinity: return "sched_getaffinity";
#endif
#ifdef __NR_sched_setaffinity
        case __NR_sched_setaffinity: return "sched_setaffinity";
#endif
#ifdef __NR_uname
        case __NR_uname: return "uname";
#endif
#ifdef __NR_sysinfo
        case __NR_sysinfo: return "sysinfo";
#endif
#ifdef __NR_process_vm_readv
        case __NR_process_vm_readv: return "process_vm_readv";
#endif
#ifdef __NR_process_vm_writev
        case __NR_process_vm_writev: return "process_vm_writev";
#endif
        default: return "unknown";
    }
}

extern "C" int32_t hookself_event_log_level(const HookselfEvent* event) {
    if (!EventValid(event)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    switch (event->kind) {
        case HOOKSELF_EVENT_INTERNAL_ERROR:
            return HOOKSELF_LOG_ERROR;
        case HOOKSELF_EVENT_SIGNAL:
            return HOOKSELF_LOG_WARN;
        case HOOKSELF_EVENT_LIFECYCLE:
            return event->action == HOOKSELF_STATE_FATAL
                           ? HOOKSELF_LOG_ERROR
                           : HOOKSELF_LOG_INFO;
        case HOOKSELF_EVENT_PROCESS:
            return HOOKSELF_LOG_INFO;
        case HOOKSELF_EVENT_PATH:
            return event->action == HOOKSELF_PATH_DENY
                           ? HOOKSELF_LOG_WARN
                           : HOOKSELF_LOG_DEBUG;
        case HOOKSELF_EVENT_SYSCALL:
            if (event->action == HOOKSELF_SYSCALL_DENY) {
                return HOOKSELF_LOG_WARN;
            }
            return event->action == HOOKSELF_SYSCALL_OBSERVE ||
                           event->action == HOOKSELF_SYSCALL_PASS
                           ? HOOKSELF_LOG_TRACE
                           : HOOKSELF_LOG_DEBUG;
        default:
            return HOOKSELF_LOG_DEBUG;
    }
}

extern "C" int32_t hookself_format_event(const HookselfEvent* event,
                                           char* message, size_t capacity,
                                           size_t* required_size) {
    if (!EventValid(event) || (message == nullptr && capacity != 0) ||
        required_size == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    TextBuilder builder(message, capacity);
    AppendFormattedEvent(&builder, *event, true);
    const size_t full_required = builder.Finish();
    if (message != nullptr && capacity != 0 && full_required >= capacity) {
        TextBuilder compact(message, capacity);
        AppendFormattedEvent(&compact, *event, false);
        const size_t compact_required = compact.Finish();
        if (compact_required >= capacity) {
            TextBuilder minimal(message, capacity);
            minimal.Append("level=");
            minimal.Append(LogLevelName(hookself_event_log_level(event)));
            minimal.Append(" kind=");
            minimal.Append(EventKindName(event->kind));
            minimal.Append(" truncated=true");
            (void)minimal.Finish();
        }
    }
    *required_size = full_required;
    return HOOKSELF_OK;
}
