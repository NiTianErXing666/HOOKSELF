#include "elf_hook/internal/memory.h"

#include <asm/unistd.h>
#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "elf_hook/internal/elf_image.h"
#include "hookself/elf_hook.h"

namespace hookself::elf_hook::internal {
namespace {

struct MemoryRegion {
    uintptr_t start;
    uintptr_t end;
    int protection;
    bool private_mapping;
};

struct PageChange {
    uintptr_t address;
    int original_protection;
    bool changed;
};

long RawSyscall6(long number, long arg0, long arg1, long arg2, long arg3,
                 long arg4, long arg5) noexcept {
#if defined(__aarch64__)
    register long x8 __asm("x8") = number;
    register long x0 __asm("x0") = arg0;
    register long x1 __asm("x1") = arg1;
    register long x2 __asm("x2") = arg2;
    register long x3 __asm("x3") = arg3;
    register long x4 __asm("x4") = arg4;
    register long x5 __asm("x5") = arg5;
    __asm__ volatile("svc 0"
                     : "+r"(x0), "+r"(x1), "+r"(x2), "+r"(x3),
                       "+r"(x4), "+r"(x5)
                     : "r"(x8)
                     : "memory", "cc");
    return x0;
#else
    (void)number;
    (void)arg0;
    (void)arg1;
    (void)arg2;
    (void)arg3;
    (void)arg4;
    (void)arg5;
    return -ENOSYS;
#endif
}

bool RawFailed(long result) noexcept {
    return result < 0 && result >= -4095;
}

long RawOpenReadOnly(const char* path) noexcept {
    return RawSyscall6(__NR_openat, AT_FDCWD,
                       reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC,
                       0, 0, 0);
}

long RawRead(int fd, void* buffer, size_t size) noexcept {
    return RawSyscall6(__NR_read, fd, reinterpret_cast<long>(buffer),
                       static_cast<long>(size), 0, 0, 0);
}

void RawClose(int fd) noexcept {
    (void)RawSyscall6(__NR_close, fd, 0, 0, 0, 0, 0);
}

int RawMprotect(uintptr_t address, size_t size, int protection) noexcept {
    const long result = RawSyscall6(
            __NR_mprotect, static_cast<long>(address),
            static_cast<long>(size), protection, 0, 0, 0);
    return RawFailed(result) ? static_cast<int>(-result) : 0;
}

uintptr_t AlignDown(uintptr_t value, size_t alignment) noexcept {
    return value & ~(static_cast<uintptr_t>(alignment) - 1U);
}

size_t PageSize() noexcept {
    static std::atomic<size_t> cached{0U};
    size_t value = cached.load(std::memory_order_acquire);
    if (value != 0U) {
        return value;
    }
    const long system_value = getpagesize();
    value = system_value >= 4096 && system_value <= 65536 &&
                    (system_value & (system_value - 1)) == 0
            ? static_cast<size_t>(system_value)
            : 4096U;
    size_t expected = 0U;
    (void)cached.compare_exchange_strong(
            expected, value, std::memory_order_release,
            std::memory_order_relaxed);
    return cached.load(std::memory_order_acquire);
}

bool ParseHex(const char** cursor, uintptr_t* value) noexcept {
    if (cursor == nullptr || *cursor == nullptr || value == nullptr) {
        return false;
    }
    uintptr_t parsed = 0U;
    size_t digits = 0U;
    while (true) {
        const char character = **cursor;
        uint32_t digit = 0U;
        if (character >= '0' && character <= '9') {
            digit = static_cast<uint32_t>(character - '0');
        } else if (character >= 'a' && character <= 'f') {
            digit = static_cast<uint32_t>(character - 'a' + 10);
        } else if (character >= 'A' && character <= 'F') {
            digit = static_cast<uint32_t>(character - 'A' + 10);
        } else {
            break;
        }
        if (parsed > (UINTPTR_MAX - digit) / 16U) {
            return false;
        }
        parsed = parsed * 16U + digit;
        ++(*cursor);
        ++digits;
    }
    if (digits == 0U) {
        return false;
    }
    *value = parsed;
    return true;
}

bool ParseRegion(const char* line, MemoryRegion* region) noexcept {
    if (line == nullptr || region == nullptr) {
        return false;
    }
    const char* cursor = line;
    uintptr_t start = 0U;
    uintptr_t end = 0U;
    if (!ParseHex(&cursor, &start) || *cursor++ != '-' ||
        !ParseHex(&cursor, &end) || *cursor++ != ' ' || end <= start) {
        return false;
    }
    int protection = 0;
    if (cursor[0] == 'r') protection |= PROT_READ;
    if (cursor[1] == 'w') protection |= PROT_WRITE;
    if (cursor[2] == 'x') protection |= PROT_EXEC;
    region->start = start;
    region->end = end;
    region->protection = protection;
    region->private_mapping = cursor[3] == 'p';
    return true;
}

class MapsReader {
public:
    explicit MapsReader(const char* path) noexcept
        : fd_(-1), begin_(0U), end_(0U), eof_(false) {
        const long result = RawOpenReadOnly(path);
        if (!RawFailed(result)) {
            fd_ = static_cast<int>(result);
        }
    }

    ~MapsReader() {
        if (fd_ >= 0) {
            RawClose(fd_);
        }
    }

    bool valid() const noexcept { return fd_ >= 0; }

    bool NextLine(char* output, size_t capacity) noexcept {
        if (output == nullptr || capacity < 2U) {
            return false;
        }
        size_t written = 0U;
        bool have_data = false;
        while (true) {
            if (begin_ == end_) {
                if (eof_) {
                    break;
                }
                const long count = RawRead(fd_, buffer_, sizeof(buffer_));
                if (RawFailed(count) || count == 0) {
                    eof_ = true;
                    break;
                }
                begin_ = 0U;
                end_ = static_cast<size_t>(count);
            }
            const char character = buffer_[begin_++];
            have_data = true;
            if (character == '\n') {
                break;
            }
            if (written + 1U < capacity) {
                output[written++] = character;
            }
        }
        output[written] = '\0';
        return have_data;
    }

private:
    int fd_;
    char buffer_[4096];
    size_t begin_;
    size_t end_;
    bool eof_;
};

bool FindMemoryRegion(uintptr_t address, size_t size,
                      MemoryRegion* region) noexcept {
    if (address == 0U || size == 0U || region == nullptr ||
        address > UINTPTR_MAX - size) {
        return false;
    }
    MapsReader reader("/proc/self/maps");
    if (!reader.valid()) {
        return false;
    }
    char line[1024];
    MemoryRegion current{};
    while (reader.NextLine(line, sizeof(line))) {
        if (!ParseRegion(line, &current)) {
            continue;
        }
        if (address >= current.start && address + size <= current.end) {
            *region = current;
            return true;
        }
        if (current.start > address) {
            break;
        }
    }
    return false;
}

bool ParseArchitectureFlags(const char* line, int* protection) noexcept {
    if (line == nullptr || protection == nullptr ||
        line[0] != 'V' || line[1] != 'm' || line[2] != 'F' ||
        line[3] != 'l' || line[4] != 'a' || line[5] != 'g' ||
        line[6] != 's' || line[7] != ':') {
        return false;
    }
    int parsed = 0;
    const char* cursor = line + 8U;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t') {
            ++cursor;
        }
        const char* const begin = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t') {
            ++cursor;
        }
        const size_t length = static_cast<size_t>(cursor - begin);
#if defined(PROT_BTI)
        if (length == 2U && begin[0] == 'b' && begin[1] == 't') {
            parsed |= PROT_BTI;
        }
#endif
#if defined(PROT_MTE)
        if (length == 2U && begin[0] == 'm' && begin[1] == 't') {
            parsed |= PROT_MTE;
        }
#endif
    }
    *protection = parsed;
    return true;
}

bool FindArchitectureProtection(uintptr_t address,
                                int* protection) noexcept {
    if (address == 0U || protection == nullptr) {
        return false;
    }
    MapsReader reader("/proc/self/smaps");
    if (!reader.valid()) {
        return false;
    }
    char line[1024];
    MemoryRegion current{};
    bool selected = false;
    while (reader.NextLine(line, sizeof(line))) {
        if (ParseRegion(line, &current)) {
            selected = address >= current.start && address < current.end;
            if (!selected && current.start > address) {
                return false;
            }
            continue;
        }
        if (selected && ParseArchitectureFlags(line, protection)) {
            return true;
        }
    }
    return false;
}

bool RestorePages(PageChange* pages, size_t count,
                  size_t page_size) noexcept {
    bool restored = true;
    while (count != 0U) {
        PageChange& page = pages[--count];
        if (!page.changed) {
            continue;
        }
        bool page_restored = false;
        for (uint32_t attempt = 0U; attempt < 3U; ++attempt) {
            if (RawMprotect(page.address, page_size,
                            page.original_protection) == 0) {
                page_restored = true;
                page.changed = false;
                break;
            }
        }
        if (!page_restored) {
            restored = false;
        }
    }
    return restored;
}

bool MakePagesWritable(PageChange* pages, size_t count,
                       size_t page_size) noexcept {
    bool writable = true;
    for (size_t index = 0; index < count; ++index) {
        if (RawMprotect(pages[index].address, page_size,
                        pages[index].original_protection | PROT_WRITE) != 0) {
            writable = false;
        } else {
            pages[index].changed =
                    (pages[index].original_protection & PROT_WRITE) == 0;
        }
    }
    return writable;
}

bool RollBackPatches(const PointerPatch* patches,
                     size_t patched_count) noexcept {
    bool rolled_back = true;
    while (patched_count != 0U) {
        const PointerPatch& patch = patches[--patched_count];
        uintptr_t observed = patch.desired;
        if (!__atomic_compare_exchange_n(
                    reinterpret_cast<uintptr_t*>(patch.address), &observed,
                    patch.expected, false, __ATOMIC_ACQ_REL,
                    __ATOMIC_ACQUIRE) && observed != patch.expected) {
            rolled_back = false;
        }
    }
    return rolled_back;
}

void SavePageProtections(const PageChange* pages, size_t count,
                         PointerPatchOutcome* outcome) noexcept {
    outcome->page_count = static_cast<uint32_t>(count);
    for (size_t index = 0U; index < count; ++index) {
        outcome->pages[index] = {
                pages[index].address, pages[index].original_protection};
    }
}

bool AnyDesiredValue(const PointerPatch* patches, size_t count) noexcept {
    for (size_t index = 0U; index < count; ++index) {
        if (__atomic_load_n(
                    reinterpret_cast<const uintptr_t*>(patches[index].address),
                    __ATOMIC_ACQUIRE) == patches[index].desired) {
            return true;
        }
    }
    return false;
}

int32_t RecoveryRequired(const PointerPatch* patches, size_t count,
                         PointerPatchOutcome* outcome) noexcept {
    outcome->recovery_required = true;
    outcome->desired_visible = AnyDesiredValue(patches, count);
    return HOOKSELF_ELF_E_RECOVERY_REQUIRED;
}

}  // namespace

bool IsExecutableAddress(uintptr_t address) noexcept {
    MemoryRegion region{};
    return address != 0U && FindMemoryRegion(address, 4U, &region) &&
            (region.protection & PROT_EXEC) != 0;
}

int32_t InspectPointerSlots(const uintptr_t* slots, size_t count,
                            uintptr_t* common_value) noexcept {
    if (slots == nullptr || common_value == nullptr || count == 0U ||
        count > kMaxSlotsPerHook) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    uintptr_t value = 0U;
    for (size_t index = 0; index < count; ++index) {
        if ((slots[index] & (alignof(uintptr_t) - 1U)) != 0U) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        MemoryRegion region{};
        if (!FindMemoryRegion(slots[index], sizeof(uintptr_t), &region) ||
            (region.protection & PROT_READ) == 0 ||
            (region.protection & PROT_EXEC) != 0 ||
            !region.private_mapping) {
            return HOOKSELF_ELF_E_PROTECTION;
        }
        const uintptr_t current = __atomic_load_n(
                reinterpret_cast<const uintptr_t*>(slots[index]),
                __ATOMIC_ACQUIRE);
        if (current == 0U) {
            return HOOKSELF_ELF_E_UNSUPPORTED_SYMBOL;
        }
        if (index == 0U) {
            value = current;
        } else if (current != value) {
            return HOOKSELF_ELF_E_CONFLICT;
        }
    }
    if (!IsExecutableAddress(value)) {
        return HOOKSELF_ELF_E_UNSUPPORTED_SYMBOL;
    }
    *common_value = value;
    return HOOKSELF_ELF_OK;
}

int32_t CommitPointerPatches(const PointerPatch* patches, size_t count,
                             PointerPatchOutcome* outcome) noexcept {
#if !defined(__aarch64__)
    (void)patches;
    (void)count;
    (void)outcome;
    return HOOKSELF_ELF_E_UNSUPPORTED_ARCH;
#else
    if (patches == nullptr || outcome == nullptr || count == 0U ||
        count > kMaxSlotsPerHook) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    *outcome = {};
    const size_t page_size = PageSize();
    PageChange pages[kMaxSlotsPerHook]{};
    size_t page_count = 0U;
    for (size_t index = 0; index < count; ++index) {
        const PointerPatch& patch = patches[index];
        if (patch.address == 0U || patch.expected == 0U ||
            patch.desired == 0U || patch.expected == patch.desired ||
            (patch.address & (alignof(uintptr_t) - 1U)) != 0U) {
            return HOOKSELF_ELF_E_INVALID_ARGUMENT;
        }
        MemoryRegion region{};
        if (!FindMemoryRegion(patch.address, sizeof(uintptr_t), &region) ||
            (region.protection & PROT_READ) == 0 ||
            (region.protection & PROT_EXEC) != 0 ||
            !region.private_mapping) {
            return HOOKSELF_ELF_E_PROTECTION;
        }
        int architecture_protection = 0;
        if (!FindArchitectureProtection(patch.address,
                                        &architecture_protection)) {
            return HOOKSELF_ELF_E_PROTECTION;
        }
        const uintptr_t page_address = AlignDown(patch.address, page_size);
        bool found = false;
        for (size_t page_index = 0; page_index < page_count; ++page_index) {
            if (pages[page_index].address == page_address) {
                if (pages[page_index].original_protection !=
                        (region.protection | architecture_protection)) {
                    return HOOKSELF_ELF_E_PROTECTION;
                }
                found = true;
                break;
            }
        }
        if (!found) {
            pages[page_count++] = {
                    page_address,
                    region.protection | architecture_protection,
                    false};
        }
    }
    SavePageProtections(pages, page_count, outcome);

    size_t writable_count = 0U;
    for (; writable_count < page_count; ++writable_count) {
        PageChange& page = pages[writable_count];
        if ((page.original_protection & PROT_WRITE) != 0) {
            continue;
        }
        if (RawMprotect(page.address, page_size,
                        page.original_protection | PROT_WRITE) != 0) {
            return RestorePages(pages, writable_count, page_size)
                    ? HOOKSELF_ELF_E_PROTECTION
                    : RecoveryRequired(patches, count, outcome);
        }
        page.changed = true;
    }

    for (size_t index = 0; index < count; ++index) {
        if (__atomic_load_n(
                    reinterpret_cast<const uintptr_t*>(patches[index].address),
                    __ATOMIC_ACQUIRE) != patches[index].expected) {
            return RestorePages(pages, page_count, page_size)
                    ? HOOKSELF_ELF_E_CONFLICT
                    : RecoveryRequired(patches, count, outcome);
        }
    }

    size_t patched_count = 0U;
    for (; patched_count < count; ++patched_count) {
        const PointerPatch& patch = patches[patched_count];
        uintptr_t observed = patch.expected;
        if (!__atomic_compare_exchange_n(
                    reinterpret_cast<uintptr_t*>(patch.address), &observed,
                    patch.desired, false, __ATOMIC_ACQ_REL,
                    __ATOMIC_ACQUIRE)) {
            const bool rolled_back = RollBackPatches(patches, patched_count);
            const bool restored = RestorePages(pages, page_count, page_size);
            return rolled_back && restored
                    ? HOOKSELF_ELF_E_CONFLICT
                    : RecoveryRequired(patches, count, outcome);
        }
    }

    if (RestorePages(pages, page_count, page_size)) {
        outcome->desired_visible = true;
        return HOOKSELF_ELF_OK;
    }

    const bool writable = MakePagesWritable(pages, page_count, page_size);
    const bool rolled_back = writable && RollBackPatches(patches, count);
    const bool restored = RestorePages(pages, page_count, page_size);
    return rolled_back && restored
            ? HOOKSELF_ELF_E_PROTECTION
            : RecoveryRequired(patches, count, outcome);
#endif
}

int32_t RecoverPointerPatches(const PointerPatch* patches, size_t count,
                              const PointerPatchOutcome& outcome) noexcept {
#if !defined(__aarch64__)
    (void)patches;
    (void)count;
    (void)outcome;
    return HOOKSELF_ELF_E_UNSUPPORTED_ARCH;
#else
    if (patches == nullptr || count == 0U || count > kMaxSlotsPerHook ||
        !outcome.recovery_required || outcome.page_count == 0U ||
        outcome.page_count > kMaxSlotsPerHook) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    const size_t page_size = PageSize();
    PageChange pages[kMaxSlotsPerHook]{};
    for (uint32_t index = 0U; index < outcome.page_count; ++index) {
        pages[index] = {
                outcome.pages[index].address,
                outcome.pages[index].protection,
                true};
    }
    if (!MakePagesWritable(pages, outcome.page_count, page_size)) {
        (void)RestorePages(pages, outcome.page_count, page_size);
        return HOOKSELF_ELF_E_RECOVERY_REQUIRED;
    }
    for (size_t index = 0U; index < count; ++index) {
        const uintptr_t current = __atomic_load_n(
                reinterpret_cast<const uintptr_t*>(patches[index].address),
                __ATOMIC_ACQUIRE);
        if (current != patches[index].expected &&
            current != patches[index].desired) {
            return RestorePages(pages, outcome.page_count, page_size)
                    ? HOOKSELF_ELF_E_CONFLICT
                    : HOOKSELF_ELF_E_RECOVERY_REQUIRED;
        }
    }
    const bool rolled_back = RollBackPatches(patches, count);
    const bool restored = RestorePages(pages, outcome.page_count, page_size);
    if (rolled_back && restored) {
        return HOOKSELF_ELF_OK;
    }
    return HOOKSELF_ELF_E_RECOVERY_REQUIRED;
#endif
}

}  // namespace hookself::elf_hook::internal
