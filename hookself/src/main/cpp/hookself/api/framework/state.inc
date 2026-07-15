struct PathRuleSlot {
    HookselfPathRule rule;
    HookselfRuleHandle handle;
    uint32_t used;
    uint32_t enabled;
    uint32_t enable_path_policy;
};

struct SyscallRuleSlot {
    HookselfSyscallRule rule;
    HookselfRuleHandle handle;
    uint32_t used;
    uint32_t enabled;
};

struct FrameworkCallFrame {
    HookselfFramework* framework;
    FrameworkCallFrame* previous;
};

pthread_mutex_t gFrameworkRegistryMutex = PTHREAD_MUTEX_INITIALIZER;
HookselfFramework* gFrameworkRegistryHead = nullptr;
thread_local FrameworkCallFrame* gFrameworkCallFrame = nullptr;

