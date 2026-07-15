uintptr_t gResidentLeaseOwner = 0;
uintptr_t gRuntimeApiBypassControl = 0;
uint32_t gRuntimeApiBypassPins = 0;
uint32_t gRuntimeApiBypassClosing = 0;
uint32_t gRuntimeApiBypassWriter = 0;
uint32_t gRuntimeApiBypassUnpinnedCalls = 0;
uint32_t gRuntimeApiBypassPublishPending = 0;
uint32_t gRuntimeApiBypassPublisher = 0;
#if defined(HOOKSELF_BUILD_TEST_SUPPORT)
uint32_t gForceVirtualPublishPostCommitFailure = 0;
#endif
pthread_mutex_t gRuntimeRegistryMutex = PTHREAD_MUTEX_INITIALIZER;
HookselfRuntime* gRuntimeRegistryHead = nullptr;
constexpr uint32_t kEventConsumerRaw = 1;
constexpr uint32_t kEventConsumerLogs = 2;
constexpr uint32_t kBypassRetireOwnerNone = 0;
constexpr uint32_t kBypassRetireOwnerCall = 1;
constexpr uint32_t kBypassRetireOwnerDestroy = 2;
thread_local int32_t gCachedLogTid = 0;

void LogCreateFailure(const char* stage, int error) noexcept {
    __android_log_print(ANDROID_LOG_WARN, "HookSelf",
                        "hookself_create stage=%s error=%d", stage, error);
}

struct RuntimeCallFrame {
    HookselfRuntime* runtime;
    RuntimeCallFrame* previous;
};

thread_local RuntimeCallFrame* gRuntimeCallFrame = nullptr;

int32_t CachedLogTid() {
    if (gCachedLogTid <= 0) {
        gCachedLogTid = static_cast<int32_t>(syscall(__NR_gettid));
    }
    return gCachedLogTid;
}

bool AcquireResidentLease(const void* owner) {
    uintptr_t expected = 0;
    return __atomic_compare_exchange_n(
            &gResidentLeaseOwner, &expected,
            reinterpret_cast<uintptr_t>(owner), false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

void ReleaseResidentLease(uintptr_t owner) {
    uintptr_t expected = owner;
    (void)__atomic_compare_exchange_n(
            &gResidentLeaseOwner, &expected, 0, false,
            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
}

void ReleaseResidentLease(const void* owner) {
    ReleaseResidentLease(reinterpret_cast<uintptr_t>(owner));
}

uint64_t MonotonicTimeNanoseconds() {
    timespec now{};
    return clock_gettime(CLOCK_MONOTONIC, &now) == 0
                   ? static_cast<uint64_t>(now.tv_sec) * 1000000000ULL +
                             static_cast<uint64_t>(now.tv_nsec)
                   : 0;
}

bool IsTracingRuntimeState(int32_t state) {
    return state == HOOKSELF_STATE_RUNNING_FULL_PTRACE ||
           state == HOOKSELF_STATE_RUNNING_SELECTIVE;
}

int BeginInternalFdOperation(
        hookself::internal::SharedControlPage* control, int32_t owner_tid,
        hookself::internal::SharedFdOperationCode opcode, int32_t source_fd,
        int32_t target_fd, uint32_t flags, uint64_t* sequence) {
    if (control == nullptr || owner_tid <= 0 || source_fd < 0 ||
        target_fd < 0 || sequence == nullptr) {
        return EINVAL;
    }
    auto* operation = &control->fd_operation;
    const uint32_t state = __atomic_load_n(&operation->state, __ATOMIC_ACQUIRE);
    if (state != static_cast<uint32_t>(
                         hookself::internal::SharedFdOperationState::kIdle)) {
        return EBUSY;
    }
    uint64_t next = __atomic_load_n(
                            &operation->request_sequence, __ATOMIC_RELAXED) +
                    1U;
    if (next == 0) {
        next = 1;
    }
    operation->owner_tid = owner_tid;
    operation->opcode = static_cast<int32_t>(opcode);
    operation->source_fd = source_fd;
    operation->target_fd = target_fd;
    operation->flags = flags;
    operation->result = INT64_MIN;
    __atomic_store_n(&operation->request_sequence, next, __ATOMIC_RELEASE);
    __atomic_store_n(
            &operation->state,
            static_cast<uint32_t>(
                    hookself::internal::SharedFdOperationState::kPending),
            __ATOMIC_RELEASE);
    *sequence = next;
    return 0;
}

bool FinishInternalFdOperation(
        hookself::internal::SharedControlPage* control, uint64_t sequence,
        int64_t expected_result) {
    if (control == nullptr || sequence == 0) {
        return false;
    }
    auto* operation = &control->fd_operation;
    const uint32_t state = __atomic_load_n(&operation->state, __ATOMIC_ACQUIRE);
    const uint64_t ack = __atomic_load_n(
            &operation->ack_sequence, __ATOMIC_ACQUIRE);
    const int64_t result = __atomic_load_n(
            &operation->result, __ATOMIC_ACQUIRE);
    const bool matched =
            state == static_cast<uint32_t>(
                             hookself::internal::SharedFdOperationState::kComplete) &&
            ack == sequence && result == expected_result;
    __atomic_store_n(
            &operation->state,
            static_cast<uint32_t>(
                    hookself::internal::SharedFdOperationState::kIdle),
            __ATOMIC_RELEASE);
    return matched;
}

bool BeginInternalProviderIo(
        hookself::internal::SharedControlPage* control, int32_t owner_tid,
        int32_t source_fd) {
    if (control == nullptr || owner_tid <= 0 || source_fd < -1 ||
        __atomic_load_n(&control->internal_bypass_active,
                        __ATOMIC_ACQUIRE) != 0) {
        return false;
    }
    control->internal_bypass_tid = owner_tid;
    control->internal_bypass_fd = source_fd;
    __atomic_store_n(&control->internal_bypass_active, 1U,
                     __ATOMIC_RELEASE);
    return true;
}

void EndInternalProviderIo(
        hookself::internal::SharedControlPage* control) {
    if (control == nullptr) {
        return;
    }
    __atomic_store_n(&control->internal_bypass_active, 0U,
                     __ATOMIC_RELEASE);
    control->internal_bypass_tid = 0;
    control->internal_bypass_fd = -1;
}

uint64_t GenerateSessionNonce(const void* runtime_address, int32_t pid, int32_t tid) {
    uint64_t nonce = 0;
#if defined(__NR_getrandom)
    if (syscall(__NR_getrandom, &nonce, sizeof(nonce), 0) ==
                static_cast<long>(sizeof(nonce)) &&
        nonce != 0) {
        return nonce;
    }
#endif
    timespec now{};
    clock_gettime(CLOCK_MONOTONIC, &now);
    nonce = static_cast<uint64_t>(now.tv_sec) * 1000000007ULL;
    nonce ^= static_cast<uint64_t>(now.tv_nsec);
    nonce ^= static_cast<uint64_t>(static_cast<uint32_t>(pid)) << 32U;
    nonce ^= static_cast<uint64_t>(static_cast<uint32_t>(tid));
    nonce ^= static_cast<uint64_t>(reinterpret_cast<uintptr_t>(runtime_address));
    return nonce == 0 ? 1 : nonce;
}

int32_t NormalizeSharedSessionResult(int32_t result) {
    if (result == HOOKSELF_E_INVALID_ARGUMENT || result == HOOKSELF_E_CAPACITY) {
        return result;
    }
    if (result == -ENOMEM) {
        return HOOKSELF_E_NO_MEMORY;
    }
    if (result == -ENOSYS) {
        return HOOKSELF_E_UNSUPPORTED;
    }
    return HOOKSELF_E_INTERNAL;
}
