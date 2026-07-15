#include "shared_abi.h"

#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace hookself::internal {
namespace {


size_t AlignUp(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

void ZeroBytes(void* memory, size_t size) {
    auto* bytes = static_cast<uint8_t*>(memory);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = 0;
    }
}

void CopyBytes(void* destination, const void* source, size_t size) {
    auto* output = static_cast<uint8_t*>(destination);
    const auto* input = static_cast<const uint8_t*>(source);
    for (size_t i = 0; i < size; ++i) {
        output[i] = input[i];
    }
}

size_t StringLength(const char* value, size_t capacity) {
    for (size_t i = 0; i < capacity; ++i) {
        if (value[i] == '\0') {
            return i;
        }
    }
    return capacity;
}

uint64_t Fnv1a64(const void* data, size_t size) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    uint64_t hash = 1469598103934665603ULL;
    for (size_t i = 0; i < size; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool RegionInsidePrefix(const SharedSessionMapping& mapping, const SharedRegion& region) {
    return mapping.prefix_mapping != nullptr && region.offset <= mapping.prefix_size &&
           region.size <= mapping.prefix_size - region.offset;
}

bool RangeInsideBank(uint32_t offset, size_t size, uint32_t bank_size) {
    return offset <= bank_size && size <= static_cast<size_t>(bank_size - offset);
}

bool ReferenceInsideArena(const SharedRuleBankHeader* bank,
                          const SharedStringRef& reference, bool require_string) {
    if (bank == nullptr || reference.offset < bank->arena_offset ||
        !RangeInsideBank(reference.offset, reference.length, bank->bank_size) ||
        reference.offset > bank->arena_offset + bank->arena_used ||
        reference.length > bank->arena_offset + bank->arena_used - reference.offset) {
        return false;
    }
    if (!require_string) {
        return true;
    }
    if (reference.length == 0) {
        return false;
    }
    const auto* base = reinterpret_cast<const uint8_t*>(bank);
    return base[reference.offset + reference.length - 1] == '\0';
}

bool BankLayoutValid(const SharedRuleBankHeader* bank, const SharedRegion& region,
                     bool populated) {
    if (bank == nullptr || region.size != SharedRuleBankBytes() ||
        bank->bank_size != region.size ||
        bank->path_rule_count > HOOKSELF_MAX_PATH_RULES ||
        bank->syscall_rule_count > HOOKSELF_MAX_SYSCALL_RULES ||
        bank->virtual_file_count > HOOKSELF_MAX_VIRTUAL_FILES ||
        !RangeInsideBank(bank->path_rules_offset,
                         sizeof(SharedPathRuleDesc) * HOOKSELF_MAX_PATH_RULES,
                         bank->bank_size) ||
        !RangeInsideBank(bank->syscall_rules_offset,
                         sizeof(SharedSyscallRuleDesc) * HOOKSELF_MAX_SYSCALL_RULES,
                         bank->bank_size) ||
        !RangeInsideBank(bank->virtual_files_offset,
                         sizeof(SharedVirtualFileDesc) * HOOKSELF_MAX_VIRTUAL_FILES,
                         bank->bank_size) ||
        !RangeInsideBank(bank->arena_offset, bank->arena_capacity, bank->bank_size) ||
        bank->arena_used > bank->arena_capacity) {
        return false;
    }
    if (!populated) {
        return bank->generation == 0 && bank->checksum == 0 &&
               bank->path_rule_count == 0 && bank->syscall_rule_count == 0 &&
               bank->virtual_file_count == 0 && bank->arena_used == 0;
    }

    const auto* base = reinterpret_cast<const uint8_t*>(bank);
    const auto* path_rules = reinterpret_cast<const SharedPathRuleDesc*>(
            base + bank->path_rules_offset);
    for (uint32_t i = 0; i < bank->path_rule_count; ++i) {
        if (!ReferenceInsideArena(bank, path_rules[i].guest_prefix, true) ||
            !ReferenceInsideArena(bank, path_rules[i].host_prefix, true)) {
            return false;
        }
    }
    const auto* virtual_files = reinterpret_cast<const SharedVirtualFileDesc*>(
            base + bank->virtual_files_offset);
    for (uint32_t i = 0; i < bank->virtual_file_count; ++i) {
        if (!ReferenceInsideArena(bank, virtual_files[i].guest_path, true) ||
            !ReferenceInsideArena(bank, virtual_files[i].backing_path, true)) {
            return false;
        }
    }
    return bank->generation != 0 &&
           bank->checksum == Fnv1a64(base + sizeof(SharedRuleBankHeader),
                                     bank->bank_size - sizeof(SharedRuleBankHeader));
}

void* PrefixAddress(const SharedSessionMapping& mapping, const SharedRegion& region) {
    if (!RegionInsidePrefix(mapping, region)) {
        return nullptr;
    }
    return static_cast<uint8_t*>(mapping.prefix_mapping) + region.offset;
}

bool WriteArenaBlob(SharedRuleBankHeader* bank, const void* data, uint32_t size,
                    SharedStringRef* reference) {
    if (size > bank->arena_capacity - bank->arena_used) {
        return false;
    }
    auto* base = reinterpret_cast<uint8_t*>(bank);
    reference->offset = bank->arena_offset + bank->arena_used;
    reference->length = size;
    if (size != 0) {
        CopyBytes(base + reference->offset, data, size);
    }
    bank->arena_used += size;
    return true;
}

bool WriteArenaString(SharedRuleBankHeader* bank, const char* value, size_t capacity,
                      SharedStringRef* reference) {
    const size_t length = StringLength(value, capacity);
    if (length == capacity || length + 1 > UINT32_MAX) {
        return false;
    }
    return WriteArenaBlob(bank, value, static_cast<uint32_t>(length + 1), reference);
}

void InitializeBankLayout(SharedRuleBankHeader* bank, size_t bank_size) {
    ZeroBytes(bank, bank_size);
    size_t offset = AlignUp(sizeof(SharedRuleBankHeader), alignof(SharedPathRuleDesc));
    bank->path_rules_offset = static_cast<uint32_t>(offset);
    offset += sizeof(SharedPathRuleDesc) * HOOKSELF_MAX_PATH_RULES;
    offset = AlignUp(offset, alignof(SharedSyscallRuleDesc));
    bank->syscall_rules_offset = static_cast<uint32_t>(offset);
    offset += sizeof(SharedSyscallRuleDesc) * HOOKSELF_MAX_SYSCALL_RULES;
    offset = AlignUp(offset, alignof(SharedVirtualFileDesc));
    bank->virtual_files_offset = static_cast<uint32_t>(offset);
    offset += sizeof(SharedVirtualFileDesc) * HOOKSELF_MAX_VIRTUAL_FILES;
    bank->arena_offset = static_cast<uint32_t>(AlignUp(offset, 64));
    bank->arena_capacity = static_cast<uint32_t>(bank_size - bank->arena_offset);
    bank->bank_size = static_cast<uint32_t>(bank_size);
}

bool SerializeConfig(const HookselfConfig& config, uint64_t generation,
                     SharedRuleBankHeader* bank, size_t bank_size,
                     const int32_t* virtual_file_fds,
                     const char* const* virtual_file_paths) {
    InitializeBankLayout(bank, bank_size);
    bank->generation = generation;
    auto* base = reinterpret_cast<uint8_t*>(bank);
    auto* path_rules = reinterpret_cast<SharedPathRuleDesc*>(base + bank->path_rules_offset);
    auto* syscall_rules =
            reinterpret_cast<SharedSyscallRuleDesc*>(base + bank->syscall_rules_offset);
    auto* virtual_files =
            reinterpret_cast<SharedVirtualFileDesc*>(base + bank->virtual_files_offset);

    for (uint32_t i = 0; i < config.path_rule_count; ++i) {
        const HookselfPathRule& source = config.path_rules[i];
        SharedPathRuleDesc& destination = path_rules[i];
        destination.rule_id = source.rule_id;
        destination.priority = source.priority;
        destination.action = source.action;
        destination.operation_mask = source.operation_mask;
        destination.flags = source.flags;
        destination.deny_errno = source.deny_errno;
        if (!WriteArenaString(bank, source.guest_prefix, sizeof(source.guest_prefix),
                              &destination.guest_prefix) ||
            !WriteArenaString(bank, source.host_prefix, sizeof(source.host_prefix),
                              &destination.host_prefix)) {
            return false;
        }
    }
    bank->path_rule_count = config.path_rule_count;

    for (uint32_t i = 0; i < config.syscall_rule_count; ++i) {
        const HookselfSyscallRule& source = config.syscall_rules[i];
        SharedSyscallRuleDesc& destination = syscall_rules[i];
        destination.rule_id = source.rule_id;
        destination.syscall_number = source.syscall_number;
        destination.action = source.action;
        destination.phase_mask = source.phase_mask;
        destination.argument_index = source.argument_index;
        destination.argument_match_mask = source.argument_match_mask;
        destination.argument_match_value = source.argument_match_value;
        destination.replacement_value = source.replacement_value;
        destination.replacement_syscall_number = source.replacement_syscall_number;
        destination.deny_errno = source.deny_errno;
        destination.flags = source.flags;
    }
    bank->syscall_rule_count = config.syscall_rule_count;

    for (uint32_t i = 0; i < config.virtual_file_count; ++i) {
        const HookselfVirtualFile& source = config.virtual_files[i];
        SharedVirtualFileDesc& destination = virtual_files[i];
        destination.file_id = source.file_id;
        destination.provider = source.provider;
        destination.mode = source.mode;
        destination.flags = source.flags;
        destination.target_fd = virtual_file_fds == nullptr
                                        ? -1
                                        : virtual_file_fds[i];
        if (!WriteArenaString(bank, source.guest_path, sizeof(source.guest_path),
                              &destination.guest_path) ||
            virtual_file_paths == nullptr ||
            !WriteArenaString(bank, virtual_file_paths[i],
                              HOOKSELF_PATH_CAPACITY,
                              &destination.backing_path)) {
            return false;
        }
    }
    bank->virtual_file_count = config.virtual_file_count;
    bank->checksum = 0;
    bank->checksum = Fnv1a64(base + sizeof(SharedRuleBankHeader),
                             bank_size - sizeof(SharedRuleBankHeader));
    return true;
}

}  // namespace

size_t SharedRuleBankBytes() {
    size_t descriptors = AlignUp(sizeof(SharedRuleBankHeader), 64);
    descriptors += sizeof(SharedPathRuleDesc) * HOOKSELF_MAX_PATH_RULES;
    descriptors = AlignUp(descriptors, alignof(SharedSyscallRuleDesc));
    descriptors += sizeof(SharedSyscallRuleDesc) * HOOKSELF_MAX_SYSCALL_RULES;
    descriptors = AlignUp(descriptors, alignof(SharedVirtualFileDesc));
    descriptors += sizeof(SharedVirtualFileDesc) * HOOKSELF_MAX_VIRTUAL_FILES;
    descriptors = AlignUp(descriptors, 64);
    const size_t string_bytes =
            static_cast<size_t>(HOOKSELF_MAX_PATH_RULES) * HOOKSELF_PATH_CAPACITY * 2U +
            static_cast<size_t>(HOOKSELF_MAX_VIRTUAL_FILES) * HOOKSELF_PATH_CAPACITY * 2U;
    return AlignUp(descriptors + string_bytes, 4096);
}

size_t SharedScratchBytes() {
    return AlignUp(sizeof(SharedScratchFrame) * kMaxTrackedTasks, 4096);
}

int32_t CreateSharedSession(const HookselfConfig& config, int32_t target_pid,
                            int32_t bootstrap_tid, uint64_t target_start_time,
                            uint64_t nonce, SharedSessionMapping* mapping,
                            const int32_t* virtual_file_fds,
                            const char* const* virtual_file_paths) {
    if (mapping == nullptr || target_pid <= 0 || bootstrap_tid <= 0) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    *mapping = {};
    const int32_t validation = hookself_validate_config(&config);
    if (validation != HOOKSELF_OK) {
        return validation;
    }
    const long page_value = sysconf(_SC_PAGESIZE);
    if (page_value <= 0 || (page_value & (page_value - 1)) != 0) {
        return HOOKSELF_E_INTERNAL;
    }
    const size_t page_size = static_cast<size_t>(page_value);
    const size_t bank_size = SharedRuleBankBytes();
    const size_t scratch_size = SharedScratchBytes();

    size_t offset = page_size;
    const SharedRegion control{offset, page_size};
    offset += page_size;
    offset = AlignUp(offset, page_size);
    const size_t event_size = AlignUp(EventRingBytes(config.event_capacity), page_size);
    const SharedRegion event_ring{offset, event_size};
    offset += event_size;
    offset = AlignUp(offset, page_size);
    const SharedRegion bank0{offset, bank_size};
    offset += bank_size;
    const SharedRegion bank1{offset, bank_size};
    offset += bank_size;
    const size_t prefix_size = AlignUp(offset, page_size);
    const SharedRegion scratch{prefix_size, scratch_size};
    const size_t total_size = prefix_size + scratch_size;
    if (total_size > UINT32_MAX) {
        return HOOKSELF_E_CAPACITY;
    }

    // This descriptor is protected by the resident and intentionally survives
    // a traced exec so the new image can retain the session backing object.
    const int fd = static_cast<int>(syscall(__NR_memfd_create, "hookself-session",
                                            0));
    if (fd < 0) {
        return -errno;
    }
    FdObjectIdentity fd_identity{};
    if (CaptureRawFdObjectIdentity(fd, &fd_identity) != 0) {
        (void)syscall(__NR_close, fd);
        return HOOKSELF_E_INTERNAL;
    }
    if (ftruncate(fd, static_cast<off_t>(total_size)) != 0) {
        const int error = errno;
        (void)CloseFdObject(fd, fd_identity);
        return -error;
    }
    void* prefix_mapping = mmap(nullptr, prefix_size, PROT_READ | PROT_WRITE,
                                MAP_SHARED, fd, 0);
    if (prefix_mapping == MAP_FAILED) {
        const int error = errno;
        (void)CloseFdObject(fd, fd_identity);
        return -error;
    }
    void* scratch_mapping = mmap(nullptr, scratch_size, PROT_READ,
                                 MAP_SHARED, fd, static_cast<off_t>(scratch.offset));
    if (scratch_mapping == MAP_FAILED) {
        const int error = errno;
        munmap(prefix_mapping, prefix_size);
        (void)CloseFdObject(fd, fd_identity);
        return -error;
    }

    ZeroBytes(prefix_mapping, prefix_size);
    auto* header = static_cast<SharedHeader*>(prefix_mapping);
    header->magic = kSharedMagic;
    header->abi_version = kSharedAbiVersion;
    header->header_size = sizeof(SharedHeader);
    header->arch = kSharedArchArm64;
    header->page_size = static_cast<uint32_t>(page_size);
    header->total_size = static_cast<uint32_t>(total_size);
    header->target_pid = target_pid;
    header->bootstrap_tid = bootstrap_tid;
    header->nonce = nonce;
    header->target_start_time = target_start_time;
    header->tracee_scratch_address = reinterpret_cast<uintptr_t>(scratch_mapping);
    header->control = control;
    header->event_ring = event_ring;
    header->rule_banks[0] = bank0;
    header->rule_banks[1] = bank1;
    header->scratch = scratch;

    auto* control_page = reinterpret_cast<SharedControlPage*>(
            static_cast<uint8_t*>(prefix_mapping) + control.offset);
    control_page->tracer_state = HOOKSELF_STATE_CONFIGURED;
    control_page->active_rule_bank = 0;
    control_page->published_generation = 1;
    control_page->protected_fd_registry_generation = 1;
    control_page->config_flags = config.flags;
    control_page->failure_mode = config.failure_mode;
    control_page->log_level = config.log_level;
    control_page->backend = config.backend;
    if (!InitializeEventRing(static_cast<uint8_t*>(prefix_mapping) + event_ring.offset,
                             event_ring.size, config.event_capacity) ||
        !SerializeConfig(config, 1,
                         reinterpret_cast<SharedRuleBankHeader*>(
                                 static_cast<uint8_t*>(prefix_mapping) + bank0.offset),
                         bank0.size, virtual_file_fds, virtual_file_paths)) {
        munmap(scratch_mapping, scratch_size);
        munmap(prefix_mapping, prefix_size);
        (void)CloseFdObject(fd, fd_identity);
        return HOOKSELF_E_CAPACITY;
    }
    InitializeBankLayout(reinterpret_cast<SharedRuleBankHeader*>(
                                 static_cast<uint8_t*>(prefix_mapping) + bank1.offset),
                         bank1.size);

    mapping->fd = fd;
    mapping->prefix_mapping = prefix_mapping;
    mapping->prefix_size = prefix_size;
    mapping->tracee_scratch_mapping = scratch_mapping;
    mapping->scratch_size = scratch_size;
    mapping->total_size = total_size;
    mapping->fd_identity = fd_identity;
    return HOOKSELF_OK;
}

int32_t PublishSharedConfig(const HookselfConfig& config,
                            SharedSessionMapping* mapping,
                            const int32_t* virtual_file_fds,
                            const char* const* virtual_file_paths) {
    if (mapping == nullptr) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    const int32_t config_validation = hookself_validate_config(&config);
    if (config_validation != HOOKSELF_OK) {
        return config_validation;
    }
    if (!ValidateSharedSession(*mapping)) {
        return HOOKSELF_E_INTERNAL;
    }
    SharedControlPage* control = GetSharedControl(*mapping);
    SharedHeader* header = GetSharedHeader(*mapping);
    const uint64_t state = __atomic_load_n(&control->tracer_state, __ATOMIC_ACQUIRE);
    if (state != HOOKSELF_STATE_CONFIGURED && state != HOOKSELF_STATE_STOPPED) {
        return HOOKSELF_E_INVALID_STATE;
    }
    const uint64_t active = __atomic_load_n(
            &control->active_rule_bank, __ATOMIC_ACQUIRE);
    const uint64_t current_generation = __atomic_load_n(
            &control->published_generation, __ATOMIC_ACQUIRE);
    if (active > 1 || current_generation == UINT64_MAX) {
        return HOOKSELF_E_INTERNAL;
    }
    const uint32_t next_bank = static_cast<uint32_t>(1U - active);
    SharedRuleBankHeader* bank = GetSharedRuleBank(*mapping, next_bank);
    if (bank == nullptr ||
        !SerializeConfig(config, current_generation + 1, bank,
                         header->rule_banks[next_bank].size,
                         virtual_file_fds, virtual_file_paths)) {
        return HOOKSELF_E_CAPACITY;
    }
    control->config_flags = config.flags;
    control->failure_mode = config.failure_mode;
    control->log_level = config.log_level;
    control->backend = config.backend;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&control->published_generation, current_generation + 1,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&control->active_rule_bank, next_bank, __ATOMIC_RELEASE);
    return HOOKSELF_OK;
}

void DestroySharedSession(SharedSessionMapping* mapping) {
    if (mapping == nullptr) {
        return;
    }
    if (mapping->tracee_scratch_mapping != nullptr) {
        munmap(mapping->tracee_scratch_mapping, mapping->scratch_size);
    }
    if (mapping->prefix_mapping != nullptr) {
        munmap(mapping->prefix_mapping, mapping->prefix_size);
    }
    if (mapping->fd >= 0) {
        (void)CloseFdObject(mapping->fd, mapping->fd_identity);
    }
    *mapping = {};
}

SharedHeader* GetSharedHeader(const SharedSessionMapping& mapping) {
    return mapping.prefix_mapping == nullptr || mapping.prefix_size < sizeof(SharedHeader)
                   ? nullptr
                   : static_cast<SharedHeader*>(mapping.prefix_mapping);
}

SharedControlPage* GetSharedControl(const SharedSessionMapping& mapping) {
    SharedHeader* header = GetSharedHeader(mapping);
    return header == nullptr
                   ? nullptr
                   : static_cast<SharedControlPage*>(PrefixAddress(mapping, header->control));
}

EventRingHeader* GetSharedEventRing(const SharedSessionMapping& mapping) {
    SharedHeader* header = GetSharedHeader(mapping);
    return header == nullptr
                   ? nullptr
                   : static_cast<EventRingHeader*>(PrefixAddress(mapping, header->event_ring));
}

SharedRuleBankHeader* GetSharedRuleBank(const SharedSessionMapping& mapping,
                                        uint32_t bank_index) {
    SharedHeader* header = GetSharedHeader(mapping);
    if (header == nullptr || bank_index >= 2) {
        return nullptr;
    }
    return static_cast<SharedRuleBankHeader*>(
            PrefixAddress(mapping, header->rule_banks[bank_index]));
}

bool ValidateSharedSession(const SharedSessionMapping& mapping) {
    SharedHeader* header = GetSharedHeader(mapping);
    if (mapping.fd < 0 ||
        CheckFdObjectIdentity(mapping.fd, mapping.fd_identity) != 0 ||
        mapping.tracee_scratch_mapping == nullptr ||
        header == nullptr || header->magic != kSharedMagic ||
        header->abi_version != kSharedAbiVersion || header->header_size != sizeof(SharedHeader) ||
        header->arch != kSharedArchArm64 || header->total_size != mapping.total_size ||
        header->page_size == 0 ||
        (header->page_size & (header->page_size - 1U)) != 0 ||
        mapping.prefix_size % header->page_size != 0 ||
        mapping.scratch_size % header->page_size != 0 ||
        mapping.total_size != mapping.prefix_size + mapping.scratch_size ||
        header->tracee_scratch_address !=
                reinterpret_cast<uintptr_t>(mapping.tracee_scratch_mapping) ||
        !RegionInsidePrefix(mapping, header->control) ||
        !RegionInsidePrefix(mapping, header->event_ring) ||
        !RegionInsidePrefix(mapping, header->rule_banks[0]) ||
        !RegionInsidePrefix(mapping, header->rule_banks[1]) ||
        header->control.size != header->page_size ||
        header->rule_banks[0].size != SharedRuleBankBytes() ||
        header->rule_banks[1].size != SharedRuleBankBytes() ||
        header->scratch.offset != mapping.prefix_size ||
        header->scratch.size != mapping.scratch_size ||
        header->scratch.size != SharedScratchBytes()) {
        return false;
    }
    EventRingHeader* ring = GetSharedEventRing(mapping);
    SharedControlPage* control = GetSharedControl(mapping);
    SharedRuleBankHeader* bank0 = GetSharedRuleBank(mapping, 0);
    SharedRuleBankHeader* bank1 = GetSharedRuleBank(mapping, 1);
    if (ring == nullptr || control == nullptr || ring->magic != kEventRingMagic ||
        ring->version != kEventRingVersion || ring->event_size != sizeof(HookselfEvent) ||
        ring->capacity == 0 || ring->capacity > HOOKSELF_MAX_EVENT_CAPACITY ||
        EventRingBytes(ring->capacity) > header->event_ring.size ||
        control->active_rule_bank > 1 || control->published_generation == 0 ||
        control->protected_fd_registry_generation == 0 ||
        control->protected_fd_count > kMaxProtectedFds ||
        control->fd_operation.state >
                static_cast<uint32_t>(SharedFdOperationState::kComplete) ||
        control->selective_install.state >
                static_cast<uint32_t>(
                        SharedSelectiveInstallState::kAmbiguousFatal) ||
        control->selective_install.filter_committed > 1U ||
        control->selective_install.policy_enabled > 1U ||
        control->teardown_bypass_active > 1U ||
        control->teardown_frozen > 1U ||
        control->teardown_release > 1U ||
        (control->teardown_bypass_active != 0U &&
         (control->teardown_bypass_tid <= 0 ||
          control->teardown_bypass_fd < 0))) {
        return false;
    }
    for (uint32_t slot = 0; slot < kMaxRuntimeApiBypassSlots; ++slot) {
        if (__atomic_load_n(&control->runtime_api_bypass_tids[slot],
                            __ATOMIC_ACQUIRE) < 0) {
            return false;
        }
    }
    const uint32_t active_bank = static_cast<uint32_t>(control->active_rule_bank);
    SharedRuleBankHeader* active = active_bank == 0 ? bank0 : bank1;
    SharedRuleBankHeader* inactive = active_bank == 0 ? bank1 : bank0;
    const SharedRegion& active_region = header->rule_banks[active_bank];
    const SharedRegion& inactive_region = header->rule_banks[1U - active_bank];
    return active != nullptr && inactive != nullptr &&
           active->generation == control->published_generation &&
           BankLayoutValid(active, active_region, true) &&
           BankLayoutValid(inactive, inactive_region, inactive->generation != 0);
}

int32_t SetProtectedFdRegistry(SharedSessionMapping* mapping,
                               const int32_t* fds, uint32_t count) {
    if (mapping == nullptr || count > kMaxProtectedFds ||
        (count != 0 && fds == nullptr)) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    SharedControlPage* control = GetSharedControl(*mapping);
    if (control == nullptr) {
        return HOOKSELF_E_INTERNAL;
    }
    __atomic_store_n(&control->protected_fd_count, 0U, __ATOMIC_RELEASE);
    uint32_t written = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (fds[i] < 0) {
            continue;
        }
        bool duplicate = false;
        for (uint32_t existing = 0; existing < written; ++existing) {
            if (control->protected_fds[existing] == fds[i]) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) {
            control->protected_fds[written++] = fds[i];
        }
    }
    __atomic_store_n(&control->protected_fd_count, written, __ATOMIC_RELEASE);
    PublishProtectedFdRegistryMutation(control);
    return HOOKSELF_OK;
}

int32_t AppendProtectedFd(SharedSessionMapping* mapping, int32_t fd) {
    if (mapping == nullptr || fd < 0) {
        return HOOKSELF_E_INVALID_ARGUMENT;
    }
    SharedControlPage* control = GetSharedControl(*mapping);
    if (control == nullptr) {
        return HOOKSELF_E_INTERNAL;
    }
    const uint32_t count = __atomic_load_n(
            &control->protected_fd_count, __ATOMIC_ACQUIRE);
    if (count > kMaxProtectedFds) {
        return HOOKSELF_E_INTERNAL;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (control->protected_fds[i] == fd) {
            return HOOKSELF_OK;
        }
    }
    if (count == kMaxProtectedFds) {
        return HOOKSELF_E_CAPACITY;
    }
    control->protected_fds[count] = fd;
    __atomic_store_n(&control->protected_fd_count, count + 1U,
                     __ATOMIC_RELEASE);
    PublishProtectedFdRegistryMutation(control);
    return HOOKSELF_OK;
}

}  // namespace hookself::internal
