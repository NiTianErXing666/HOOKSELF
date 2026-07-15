struct HookselfRuntime {
    pthread_mutex_t mutex;
    pthread_mutex_t event_reader_mutex;
    pthread_cond_t lifecycle_cv;
    uint32_t active_calls;
    uint32_t closing;
    uint32_t deferred_destroy;
    uint32_t destroy_waiter;
    uint32_t drain_abort_requested;
    uint32_t bypass_retire_owner;
    HookselfRuntime* registry_next;
    int32_t state;
    HookselfConfig config;
    HookselfPathRule path_rules[HOOKSELF_MAX_PATH_RULES];
    HookselfSyscallRule syscall_rules[HOOKSELF_MAX_SYSCALL_RULES];
    HookselfVirtualFile virtual_files[HOOKSELF_MAX_VIRTUAL_FILES];
    uint8_t* virtual_contents[HOOKSELF_MAX_VIRTUAL_FILES];
    hookself::internal::VirtualFileBacking
            virtual_backings[HOOKSELF_MAX_VIRTUAL_FILES];
    hookself::internal::VirtualBackingSession virtual_backing_session;
    int32_t virtual_provider_source_fds[HOOKSELF_MAX_VIRTUAL_FILES];
    hookself::internal::FdObjectIdentity
            virtual_provider_source_identities[HOOKSELF_MAX_VIRTUAL_FILES];
    uint32_t virtual_provider_uses_configured_content[HOOKSELF_MAX_VIRTUAL_FILES];
    uint8_t* virtual_provider_scratch;
    size_t virtual_provider_scratch_size;
    int32_t virtual_file_fds[HOOKSELF_MAX_VIRTUAL_FILES];
    hookself::internal::SharedSessionMapping shared_session{};
    hookself::internal::ResidentSessionController resident_controller{};
    hookself::internal::EventRingHeader* event_ring;
    HookselfStats stats;
    HookselfLogSink log_sink;
    void* log_sink_user_data;
    uint32_t event_consumer_mode;
    uint32_t resident_lease_owned;
    int32_t target_pid;
};
