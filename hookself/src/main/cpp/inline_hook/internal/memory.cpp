#include "inline_hook/internal/memory.h"

#include <asm/unistd.h>
#include <atomic>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "hookself/inline_hook.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace hookself::inline_hook::internal {
namespace {

constexpr uintptr_t kMinimumUserAddress = 0x10000U;

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
                       reinterpret_cast<long>(path),
                       O_RDONLY | O_CLOEXEC, 0, 0, 0);
}

long RawRead(int fd, void* buffer, size_t size) noexcept {
    return RawSyscall6(__NR_read, fd, reinterpret_cast<long>(buffer),
                       static_cast<long>(size), 0, 0, 0);
}

void RawClose(int fd) noexcept {
    (void)RawSyscall6(__NR_close, fd, 0, 0, 0, 0, 0);
}

int RawMprotect(void* address, size_t size, int protection) noexcept {
    const long result = RawSyscall6(
            __NR_mprotect, reinterpret_cast<long>(address),
            static_cast<long>(size), protection, 0, 0, 0);
    return RawFailed(result) ? static_cast<int>(-result) : 0;
}

void* RawMmap(void* address, size_t size, int protection, int flags) noexcept {
    const long result = RawSyscall6(
            __NR_mmap, reinterpret_cast<long>(address),
            static_cast<long>(size), protection, flags, -1, 0);
    return RawFailed(result) ? nullptr : reinterpret_cast<void*>(result);
}

void RawMunmap(void* address, size_t size) noexcept {
    (void)RawSyscall6(__NR_munmap, reinterpret_cast<long>(address),
                      static_cast<long>(size), 0, 0, 0, 0);
}

uintptr_t AlignDown(uintptr_t value, size_t alignment) noexcept {
    return value & ~(static_cast<uintptr_t>(alignment) - 1U);
}

uintptr_t AlignUp(uintptr_t value, size_t alignment) noexcept {
    const uintptr_t mask = static_cast<uintptr_t>(alignment) - 1U;
    if (value > UINTPTR_MAX - mask) {
        return 0;
    }
    return (value + mask) & ~mask;
}

bool ParseHex(const char** cursor, uintptr_t* value) noexcept {
    if (cursor == nullptr || *cursor == nullptr || value == nullptr) {
        return false;
    }
    uintptr_t parsed = 0;
    size_t digits = 0;
    while (true) {
        const char ch = **cursor;
        uint32_t digit = 0;
        if (ch >= '0' && ch <= '9') {
            digit = static_cast<uint32_t>(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            digit = static_cast<uint32_t>(ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            digit = static_cast<uint32_t>(ch - 'A' + 10);
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
    uintptr_t start = 0;
    uintptr_t end = 0;
    if (!ParseHex(&cursor, &start) || *cursor++ != '-' ||
        !ParseHex(&cursor, &end) || *cursor++ != ' ' || end <= start) {
        return false;
    }
    int protection = 0;
    if (cursor[0] == 'r') {
        protection |= PROT_READ;
    }
    if (cursor[1] == 'w') {
        protection |= PROT_WRITE;
    }
    if (cursor[2] == 'x') {
        protection |= PROT_EXEC;
    }
    region->start = start;
    region->end = end;
    region->protection = protection;
    region->private_mapping = cursor[3] == 'p';
    return true;
}

class MapsReader {
public:
    explicit MapsReader(const char* path = "/proc/self/maps") noexcept
        : fd_(-1), begin_(0), end_(0), eof_(false) {
        const long fd = RawOpenReadOnly(path);
        if (!RawFailed(fd)) {
            fd_ = static_cast<int>(fd);
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
        size_t written = 0;
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
                begin_ = 0;
                end_ = static_cast<size_t>(count);
            }
            const char ch = buffer_[begin_++];
            have_data = true;
            if (ch == '\n') {
                break;
            }
            if (written + 1U < capacity) {
                output[written++] = ch;
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

bool ParseArchitectureVmFlags(const char* line,
                              int* protection) noexcept {
    if (line == nullptr || protection == nullptr) {
        return false;
    }
    constexpr char kPrefix[] = "VmFlags:";
    for (size_t index = 0; index < sizeof(kPrefix) - 1U; ++index) {
        if (line[index] != kPrefix[index]) {
            return false;
        }
    }

    int parsed = 0;
    const char* cursor = line + sizeof(kPrefix) - 1U;
    while (*cursor != '\0') {
        while (*cursor == ' ' || *cursor == '\t') {
            ++cursor;
        }
        const char* const begin = cursor;
        while (*cursor != '\0' && *cursor != ' ' && *cursor != '\t') {
            ++cursor;
        }
        const size_t length = static_cast<size_t>(cursor - begin);
#if defined(__aarch64__)
        if (length == 2U && begin[0] == 'b' && begin[1] == 't') {
            parsed |= PROT_BTI;
        } else if (length == 2U && begin[0] == 'm' && begin[1] == 't') {
            parsed |= PROT_MTE;
        }
#else
        (void)length;
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
    bool selected = false;
    char line[1024];
    MemoryRegion current{};
    while (reader.NextLine(line, sizeof(line))) {
        if (ParseRegion(line, &current)) {
            selected = address >= current.start && address < current.end;
            if (!selected && current.start > address) {
                return false;
            }
            continue;
        }
        if (selected && ParseArchitectureVmFlags(line, protection)) {
            return true;
        }
    }
    return false;
}

void* TryMapAt(uintptr_t candidate, size_t page_size,
               uintptr_t reference, uint64_t range) noexcept {
    void* mapped = RawMmap(
            reinterpret_cast<void*>(candidate), page_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE);
    if (mapped == nullptr) {
        mapped = RawMmap(reinterpret_cast<void*>(candidate), page_size,
                         PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS);
    }
    if (mapped == nullptr) {
        return nullptr;
    }
    const uintptr_t address = reinterpret_cast<uintptr_t>(mapped);
    const uint64_t distance = address >= reference
            ? static_cast<uint64_t>(address - reference)
            : static_cast<uint64_t>(reference - address);
    if ((address & (page_size - 1U)) != 0U || distance >= range) {
        RawMunmap(mapped, page_size);
        return nullptr;
    }
    return mapped;
}

void* TryMapGap(uintptr_t gap_start, uintptr_t gap_end,
                uintptr_t reference, uint64_t range,
                size_t page_size) noexcept {
    const uintptr_t first = AlignUp(gap_start, page_size);
    if (first == 0U || gap_end < page_size || first > gap_end - page_size) {
        return nullptr;
    }
    const uintptr_t last = AlignDown(gap_end - page_size, page_size);
    uintptr_t candidate = first;
    if (reference >= first && reference <= last) {
        candidate = AlignDown(reference, page_size);
    } else if (reference > last) {
        candidate = last;
    }
    void* mapped = TryMapAt(candidate, page_size, reference, range);
    if (mapped == nullptr && candidate != first) {
        mapped = TryMapAt(first, page_size, reference, range);
    }
    if (mapped == nullptr && candidate != last && first != last) {
        mapped = TryMapAt(last, page_size, reference, range);
    }
    return mapped;
}

size_t ReadAuxvPageSize() noexcept {
    const long fd_result = RawOpenReadOnly("/proc/self/auxv");
    if (RawFailed(fd_result)) {
        return 0;
    }
    const int fd = static_cast<int>(fd_result);
    Elf64_auxv_t entries[16];
    size_t page_size = 0;
    while (true) {
        const long count = RawRead(fd, entries, sizeof(entries));
        if (RawFailed(count) || count == 0) {
            break;
        }
        const size_t entry_count = static_cast<size_t>(count) /
                sizeof(entries[0]);
        for (size_t index = 0; index < entry_count; ++index) {
            if (entries[index].a_type == AT_PAGESZ) {
                page_size = static_cast<size_t>(entries[index].a_un.a_val);
                break;
            }
        }
        if (page_size != 0U) {
            break;
        }
    }
    RawClose(fd);
    return page_size;
}

}  // namespace

size_t PageSize() noexcept {
    static std::atomic<size_t> cached{0};
    size_t value = cached.load(std::memory_order_acquire);
    if (value != 0U) {
        return value;
    }
    value = ReadAuxvPageSize();
    if (value < 4096U || value > 65536U || (value & (value - 1U)) != 0U) {
        const long fallback = getpagesize();
        value = fallback > 0 ? static_cast<size_t>(fallback) : 4096U;
    }
    size_t expected = 0;
    (void)cached.compare_exchange_strong(
            expected, value, std::memory_order_release,
            std::memory_order_relaxed);
    return cached.load(std::memory_order_acquire);
}

bool FindMemoryRegion(uintptr_t address, size_t size,
                      MemoryRegion* region) noexcept {
    if (address == 0U || size == 0U || region == nullptr ||
        address > UINTPTR_MAX - size) {
        return false;
    }
    MapsReader reader;
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

void* AllocateNearCodePage(uintptr_t reference,
                           uint64_t range) noexcept {
    const size_t page_size = PageSize();
    if (reference < kMinimumUserAddress || range <= page_size) {
        return nullptr;
    }
    const uintptr_t lower = reference > range
            ? AlignUp(reference - static_cast<uintptr_t>(range), page_size)
            : kMinimumUserAddress;
    const uintptr_t upper_unaligned = reference > UINTPTR_MAX - range
            ? UINTPTR_MAX - page_size
            : reference + static_cast<uintptr_t>(range) - page_size;
    const uintptr_t upper = AlignDown(upper_unaligned, page_size);
    if (lower == 0U || lower > upper) {
        return nullptr;
    }

    MapsReader reader;
    if (!reader.valid()) {
        return nullptr;
    }
    uintptr_t previous_end = kMinimumUserAddress;
    char line[1024];
    MemoryRegion current{};
    while (reader.NextLine(line, sizeof(line))) {
        if (!ParseRegion(line, &current)) {
            continue;
        }
        const uintptr_t gap_start = previous_end > lower
                ? previous_end : lower;
        const uintptr_t gap_end = current.start < upper + page_size
                ? current.start : upper + page_size;
        if (gap_start < gap_end) {
            void* mapped = TryMapGap(gap_start, gap_end, reference, range,
                                     page_size);
            if (mapped != nullptr) {
                return mapped;
            }
        }
        if (current.end > previous_end) {
            previous_end = current.end;
        }
        if (previous_end > upper) {
            break;
        }
    }
    if (previous_end <= upper) {
        return TryMapGap(previous_end > lower ? previous_end : lower,
                         upper + page_size, reference, range, page_size);
    }
    return nullptr;
}

void FlushInstructionCache(uintptr_t start, size_t size) noexcept {
#if defined(__aarch64__)
    if (size == 0U || start > UINTPTR_MAX - size) {
        return;
    }
    uint64_t ctr = 0;
    __asm__ volatile("mrs %0, ctr_el0" : "=r"(ctr));
    const uintptr_t end = start + size;
    if (((ctr >> 28U) & 1U) == 0U) {
        const uintptr_t line = static_cast<uintptr_t>(4U) <<
                ((ctr >> 16U) & 0xfU);
        for (uintptr_t cursor = start & ~(line - 1U); cursor < end;
             cursor += line) {
            __asm__ volatile("dc cvau, %0" : : "r"(cursor) : "memory");
        }
    }
    __asm__ volatile("dsb ish" : : : "memory");
    if (((ctr >> 29U) & 1U) == 0U) {
        const uintptr_t line = static_cast<uintptr_t>(4U) <<
                (ctr & 0xfU);
        for (uintptr_t cursor = start & ~(line - 1U); cursor < end;
             cursor += line) {
            __asm__ volatile("ic ivau, %0" : : "r"(cursor) : "memory");
        }
        __asm__ volatile("dsb ish" : : : "memory");
    }
    __asm__ volatile("isb" : : : "memory");
#else
    (void)start;
    (void)size;
#endif
}

int32_t FinalizeCodePage(void* page, size_t used_size) noexcept {
    if (page == nullptr || used_size == 0U || used_size > PageSize()) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    FlushInstructionCache(reinterpret_cast<uintptr_t>(page), used_size);
    if (RawMprotect(page, PageSize(), PROT_READ | PROT_EXEC) != 0) {
        return HOOKSELF_INLINE_E_PROTECTION;
    }
    return HOOKSELF_INLINE_OK;
}

void ReleaseUnpublishedPage(void* page) noexcept {
    if (page != nullptr) {
        RawMunmap(page, PageSize());
    }
}

int32_t ReadExecutableInstruction(uintptr_t address,
                                  uint32_t* instruction) noexcept {
    if (instruction == nullptr || (address & 3U) != 0U) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    MemoryRegion region{};
    if (!FindMemoryRegion(address, sizeof(uint32_t), &region) ||
        (region.protection & (PROT_READ | PROT_EXEC)) !=
                (PROT_READ | PROT_EXEC) ||
        !region.private_mapping) {
        return HOOKSELF_INLINE_E_PROTECTION;
    }
    *instruction = __atomic_load_n(
            reinterpret_cast<const uint32_t*>(address), __ATOMIC_ACQUIRE);
    return HOOKSELF_INLINE_OK;
}

int32_t PatchExecutableInstruction(uintptr_t address, uint32_t expected,
                                   uint32_t replacement) noexcept {
    if ((address & 3U) != 0U) {
        return HOOKSELF_INLINE_E_INVALID_ARGUMENT;
    }
    MemoryRegion region{};
    if (!FindMemoryRegion(address, sizeof(uint32_t), &region) ||
        (region.protection & (PROT_READ | PROT_EXEC)) !=
                (PROT_READ | PROT_EXEC) ||
        !region.private_mapping) {
        return HOOKSELF_INLINE_E_PROTECTION;
    }
    int architecture_protection = 0;
    if (!FindArchitectureProtection(address, &architecture_protection)) {
        return HOOKSELF_INLINE_E_PROTECTION;
    }
    const size_t page_size = PageSize();
    void* const page = reinterpret_cast<void*>(AlignDown(address, page_size));
    const int original_protection =
            region.protection | architecture_protection;
    const int writable_protection = original_protection | PROT_WRITE;
    if (RawMprotect(page, page_size, writable_protection) != 0) {
        return HOOKSELF_INLINE_E_PROTECTION;
    }

    auto* const word = reinterpret_cast<uint32_t*>(address);
    uint32_t observed = expected;
    if (!__atomic_compare_exchange_n(
                word, &observed, replacement, false,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        return RawMprotect(page, page_size, original_protection) == 0
                ? HOOKSELF_INLINE_E_CONFLICT
                : HOOKSELF_INLINE_E_PROTECTION;
    }
    FlushInstructionCache(address, sizeof(uint32_t));

    if (RawMprotect(page, page_size, original_protection) == 0) {
        return HOOKSELF_INLINE_OK;
    }

    observed = replacement;
    if (__atomic_compare_exchange_n(
                word, &observed, expected, false,
                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        FlushInstructionCache(address, sizeof(uint32_t));
    }
    (void)RawMprotect(page, page_size, original_protection);
    return HOOKSELF_INLINE_E_PROTECTION;
}

}  // namespace hookself::inline_hook::internal
