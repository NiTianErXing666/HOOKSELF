#include <jni.h>

#include <asm/hwcap.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cinttypes>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "hookself/inline_hook.h"

namespace {

using FixtureFn = uint64_t (*)(uint64_t);
using FixtureInvoker = uint64_t (*)(FixtureFn, uint64_t);
using ExpectedFn = uint64_t (*)(uint64_t);

extern "C" {
uint64_t hs_inline_fixture_plain(uint64_t);
uint64_t hs_inline_fixture_adr(uint64_t);
uint64_t hs_inline_fixture_adrp(uint64_t);
uint64_t hs_inline_fixture_literal_w(uint64_t);
uint64_t hs_inline_fixture_literal_x(uint64_t);
uint64_t hs_inline_fixture_ldrsw(uint64_t);
uint64_t hs_inline_fixture_literal_s(uint64_t);
uint64_t hs_inline_fixture_literal_d(uint64_t);
uint64_t hs_inline_fixture_literal_q(uint64_t);
uint64_t hs_inline_fixture_prfm(uint64_t);
uint64_t hs_inline_fixture_b(uint64_t);
uint64_t hs_inline_fixture_bl(uint64_t);
uint64_t hs_inline_fixture_bcond(uint64_t);
uint64_t hs_inline_fixture_cbz(uint64_t);
uint64_t hs_inline_fixture_cbnz(uint64_t);
uint64_t hs_inline_fixture_tbz(uint64_t);
uint64_t hs_inline_fixture_tbnz(uint64_t);
uint64_t hs_inline_fixture_bti(uint64_t);
uint64_t hs_inline_fixture_paciasp(uint64_t);
uint64_t hs_inline_fixture_pacibsp(uint64_t);
uint64_t hs_inline_fixture_convenience(uint64_t);
uint64_t hs_inline_fixture_multi_a(uint64_t);
uint64_t hs_inline_fixture_multi_b(uint64_t);
uint64_t hs_inline_fixture_concurrent(uint64_t);
uint64_t hs_inline_fixture_unsupported_blr(uint64_t);
uint64_t hs_inline_fixture_invoke_bl(FixtureFn, uint64_t);
uint64_t hs_inline_fixture_invoke_bcond(FixtureFn, uint64_t);
extern const uint8_t hs_inline_fixture_adr_value[];
}

constexpr uint64_t kReplacementDelta = UINT64_C(0x100000);
constexpr uint32_t kRequiredInfoFlags =
        HOOKSELF_INLINE_INFO_F_TRAMPOLINE_RETAINED;

struct TestStats {
    uint32_t checks = 0;
    uint32_t failures = 0;
    uint32_t fixtures = 0;
    uint32_t expanded_relocations = 0;
    uint32_t bti_paths = 0;
    uint32_t bti_guarded_supported = 0;
    uint32_t bti_guarded_paths = 0;
    uint32_t bti_guarded_far_bridge = 0;
    uint32_t pac_paths = 0;
    uint32_t unsupported_relocations = 0;
    uint32_t rwx_violations = 0;
    uint64_t concurrent_calls = 0;
    std::string first_failure;

    void Check(bool condition, const std::string& message) {
        ++checks;
        if (condition) {
            return;
        }
        ++failures;
        if (first_failure.empty()) {
            first_failure = message;
        }
    }
};

struct Mapping {
    bool found = false;
    bool readable = false;
    bool writable = false;
    bool executable = false;
};

struct FixtureCase {
    const char* name;
    FixtureFn target;
    FixtureInvoker invoke;
    ExpectedFn expected;
    uint32_t required_flags;
};

__attribute__((noinline)) uint64_t InvokeDirect(
        FixtureFn function, uint64_t argument) {
    return function(argument);
}

__attribute__((noinline)) uint64_t InlineReplacement(uint64_t argument) {
    return argument + kReplacementDelta;
}

uint64_t ExpectedPlain(uint64_t value) { return value + 7U; }
uint64_t ExpectedAdr(uint64_t) {
    return reinterpret_cast<uintptr_t>(hs_inline_fixture_adr_value);
}
uint64_t ExpectedAdrp(uint64_t) {
    return reinterpret_cast<uintptr_t>(hs_inline_fixture_adrp) &
            ~static_cast<uintptr_t>(0xfffU);
}
uint64_t ExpectedLiteralW(uint64_t) { return UINT64_C(0x89abcdef); }
uint64_t ExpectedLiteralX(uint64_t) { return UINT64_C(0x0123456789abcdef); }
uint64_t ExpectedLdrsw(uint64_t) {
    return static_cast<uint64_t>(static_cast<int64_t>(-1234567));
}
uint64_t ExpectedLiteralS(uint64_t) { return UINT64_C(0x3f9e0419); }
uint64_t ExpectedLiteralD(uint64_t) { return UINT64_C(0x400921fb54442d18); }
uint64_t ExpectedLiteralQ(uint64_t) { return UINT64_C(0x1122334455667788); }
uint64_t ExpectedPrfm(uint64_t) { return UINT64_C(0x5a); }
uint64_t ExpectedB(uint64_t value) { return value + 9U; }
uint64_t ExpectedBl(uint64_t) {
    return reinterpret_cast<uintptr_t>(hs_inline_fixture_bl) + 4U;
}
uint64_t ExpectedBcond(uint64_t value) { return value == 0U ? 0x32U : 0x31U; }
uint64_t ExpectedCbz(uint64_t value) { return value == 0U ? 0x42U : 0x41U; }
uint64_t ExpectedCbnz(uint64_t value) { return value != 0U ? 0x44U : 0x43U; }
uint64_t ExpectedTbz(uint64_t value) { return (value & 1U) == 0U ? 0x52U : 0x51U; }
uint64_t ExpectedTbnz(uint64_t value) { return (value & 1U) != 0U ? 0x54U : 0x53U; }
uint64_t ExpectedBti(uint64_t value) { return value + 13U; }
uint64_t ExpectedPaciasp(uint64_t value) { return value + 15U; }
uint64_t ExpectedPacibsp(uint64_t value) { return value + 17U; }

uint64_t InvokeBl(FixtureFn function, uint64_t argument) {
    return hs_inline_fixture_invoke_bl(function, argument);
}

uint64_t InvokeBcond(FixtureFn function, uint64_t argument) {
    return hs_inline_fixture_invoke_bcond(function, argument);
}

uintptr_t Address(FixtureFn function) {
    return reinterpret_cast<uintptr_t>(function);
}

void* Pointer(FixtureFn function) {
    return reinterpret_cast<void*>(Address(function));
}

std::string ResultMessage(const char* operation, int32_t result) {
    std::ostringstream stream;
    stream << operation << '=' << hookself_inline_result_string(result)
           << '(' << result << ')';
    return stream.str();
}

Mapping FindMapping(uintptr_t address) {
    std::ifstream maps("/proc/self/maps");
    std::string line;
    while (std::getline(maps, line)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char permissions[5] = {};
        if (std::sscanf(line.c_str(), "%llx-%llx %4s", &start, &end,
                        permissions) != 3 ||
            address < static_cast<uintptr_t>(start) ||
            address >= static_cast<uintptr_t>(end)) {
            continue;
        }
        Mapping mapping{};
        mapping.found = true;
        mapping.readable = permissions[0] == 'r';
        mapping.writable = permissions[1] == 'w';
        mapping.executable = permissions[2] == 'x';
        return mapping;
    }
    return {};
}

bool MappingHasVmFlag(uintptr_t address, const char* expected_flag) {
    if (expected_flag == nullptr || expected_flag[0] == '\0') {
        return false;
    }
    std::ifstream smaps("/proc/self/smaps");
    std::string line;
    bool selected = false;
    while (std::getline(smaps, line)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char permissions[5] = {};
        if (std::sscanf(line.c_str(), "%llx-%llx %4s", &start, &end,
                        permissions) == 3) {
            if (selected) {
                return false;
            }
            selected = address >= static_cast<uintptr_t>(start) &&
                    address < static_cast<uintptr_t>(end);
            continue;
        }
        if (!selected || line.rfind("VmFlags:", 0U) != 0U) {
            continue;
        }
        std::istringstream flags(line.substr(sizeof("VmFlags:") - 1U));
        std::string flag;
        while (flags >> flag) {
            if (flag == expected_flag) {
                return true;
            }
        }
        return false;
    }
    return false;
}

void CheckExecutableMapping(TestStats* stats, uintptr_t address,
                            const std::string& label) {
    const Mapping mapping = FindMapping(address);
    stats->Check(mapping.found, label + ": mapping missing");
    stats->Check(mapping.readable, label + ": mapping is not readable");
    stats->Check(mapping.executable, label + ": mapping is not executable");
    const bool rwx = mapping.writable && mapping.executable;
    if (rwx) {
        ++stats->rwx_violations;
    }
    stats->Check(!rwx, label + ": mapping retained RWX permissions");
}

void TestApiContract(TestStats* stats) {
    stats->Check(hookself_inline_get_abi_version() ==
                         HOOKSELF_INLINE_ABI_VERSION,
                 "ABI version mismatch");

    HookselfInlineOptions options{};
    hookself_inline_default_options(&options);
    stats->Check(options.struct_size == sizeof(options),
                 "default options size mismatch");
    stats->Check(options.abi_version == HOOKSELF_INLINE_ABI_VERSION,
                 "default options ABI mismatch");
    stats->Check(hookself_inline_validate_options(&options) ==
                         HOOKSELF_INLINE_OK,
                 "default options rejected");

    HookselfInlineOptions invalid = options;
    invalid.abi_version += 1U;
    stats->Check(hookself_inline_validate_options(&invalid) ==
                         HOOKSELF_INLINE_E_ABI_MISMATCH,
                 "ABI mismatch was not rejected");
    invalid = options;
    invalid.reserved[0] = 1U;
    stats->Check(hookself_inline_validate_options(&invalid) ==
                         HOOKSELF_INLINE_E_INVALID_ARGUMENT,
                 "reserved option was not rejected");

    HookselfInlineCapabilities capabilities{};
    capabilities.struct_size = sizeof(capabilities);
    const int32_t result = hookself_inline_get_capabilities(&capabilities);
    stats->Check(result == HOOKSELF_INLINE_OK,
                 ResultMessage("get_capabilities", result));
    const uint64_t required_features =
            HOOKSELF_INLINE_FEATURE_ATOMIC_ARM64_BRANCH |
            HOOKSELF_INLINE_FEATURE_NEAR_BRIDGE |
            HOOKSELF_INLINE_FEATURE_ORIGINAL_TRAMPOLINE |
            HOOKSELF_INLINE_FEATURE_PC_RELATIVE_RELOCATION |
            HOOKSELF_INLINE_FEATURE_BTI_ENTRY |
            HOOKSELF_INLINE_FEATURE_PAC_ENTRY |
            HOOKSELF_INLINE_FEATURE_RETAINED_TRAMPOLINE |
            HOOKSELF_INLINE_FEATURE_THREAD_SAFE_REGISTRY;
    stats->Check((capabilities.features & required_features) ==
                         required_features,
                 "required ARM64 capabilities missing");
    stats->Check(capabilities.instruction_size == 4U &&
                         capabilities.patch_size == 4U,
                 "ARM64 patch geometry mismatch");
    stats->Check(capabilities.max_active_hooks >= 2U,
                 "active hook capacity is too small");
    stats->Check(hookself_inline_remove(HOOKSELF_INLINE_INVALID_HANDLE) ==
                         HOOKSELF_INLINE_E_INVALID_ARGUMENT,
                 "invalid handle removal result mismatch");
    void* invalid_original = reinterpret_cast<void*>(
            static_cast<uintptr_t>(UINT64_C(0x12345678)));
    HookselfInlineHandle invalid_handle = UINT64_C(0xabcdef0123456789);
    const void* const invalid_original_before = invalid_original;
    const HookselfInlineHandle invalid_handle_before = invalid_handle;
    const int32_t invalid_install = hookself_inline_install(
            nullptr, Pointer(InlineReplacement), nullptr,
            &invalid_original, &invalid_handle);
    stats->Check(invalid_install == HOOKSELF_INLINE_E_INVALID_ARGUMENT,
                 "invalid install result mismatch");
    stats->Check(invalid_original == invalid_original_before &&
                         invalid_handle == invalid_handle_before,
                 "invalid install modified output storage");
    stats->Check(std::string(hookself_inline_result_string(
                         HOOKSELF_INLINE_E_ALREADY_INSTALLED)) ==
                         "ALREADY_INSTALLED",
                 "result string mismatch");
}

void TestUnsupportedRelocation(TestStats* stats) {
    const FixtureFn target = hs_inline_fixture_unsupported_blr;
    const uintptr_t target_address = Address(target);
    const uint32_t instruction_before = __atomic_load_n(
            reinterpret_cast<const uint32_t*>(target_address),
            __ATOMIC_ACQUIRE);
    void* original = reinterpret_cast<void*>(
            static_cast<uintptr_t>(UINT64_C(0x23456789)));
    HookselfInlineHandle handle = UINT64_C(0x123456789abcdef0);
    void* const original_before = original;
    const HookselfInlineHandle handle_before = handle;

    const int32_t install = hookself_inline_install(
            Pointer(target), Pointer(InlineReplacement), nullptr,
            &original, &handle);
    stats->Check(install == HOOKSELF_INLINE_E_RELOCATION,
                 ResultMessage("unsupported BLR install", install));
    if (install == HOOKSELF_INLINE_E_RELOCATION) {
        ++stats->unsupported_relocations;
    }
    stats->Check(original == original_before && handle == handle_before,
                 "unsupported BLR install modified output storage");
    const uint32_t instruction_after = __atomic_load_n(
            reinterpret_cast<const uint32_t*>(target_address),
            __ATOMIC_ACQUIRE);
    stats->Check(instruction_after == instruction_before,
                 "unsupported BLR install modified target instruction");

    HookselfInlineHandle found = UINT64_C(0xfedcba9876543210);
    const int32_t find = hookself_inline_find(Pointer(target), &found);
    stats->Check(find == HOOKSELF_INLINE_E_NOT_FOUND,
                 ResultMessage("unsupported BLR find", find));

    if (find == HOOKSELF_INLINE_OK) {
        stats->Check(hookself_inline_remove(found) == HOOKSELF_INLINE_OK,
                     "unsupported BLR cleanup by find failed");
    } else if (install == HOOKSELF_INLINE_OK &&
               handle != HOOKSELF_INLINE_INVALID_HANDLE) {
        stats->Check(hookself_inline_remove(handle) == HOOKSELF_INLINE_OK,
                     "unsupported BLR cleanup by handle failed");
    }
}

void TestFixture(TestStats* stats, const FixtureCase& fixture,
                 bool test_duplicate) {
    constexpr uint64_t kArguments[] = {0U, 5U};
    for (uint64_t argument : kArguments) {
        stats->Check(fixture.invoke(fixture.target, argument) ==
                             fixture.expected(argument),
                     std::string(fixture.name) + ": baseline mismatch");
    }

    HookselfInlineOptions options{};
    hookself_inline_default_options(&options);
    void* original_raw = nullptr;
    HookselfInlineHandle handle = HOOKSELF_INLINE_INVALID_HANDLE;
    const int32_t install = hookself_inline_install(
            Pointer(fixture.target), Pointer(InlineReplacement), &options,
            &original_raw, &handle);
    stats->Check(install == HOOKSELF_INLINE_OK,
                 std::string(fixture.name) + ": " +
                         ResultMessage("install", install));
    if (install != HOOKSELF_INLINE_OK) {
        (void)hookself_inline_unhook(Pointer(fixture.target));
        return;
    }

    ++stats->fixtures;
    stats->Check(original_raw != nullptr, std::string(fixture.name) +
                         ": original pointer missing");
    stats->Check(handle != HOOKSELF_INLINE_INVALID_HANDLE,
                 std::string(fixture.name) + ": handle missing");
    const auto original = reinterpret_cast<FixtureFn>(original_raw);

    HookselfInlineHandle found = HOOKSELF_INLINE_INVALID_HANDLE;
    const int32_t find = hookself_inline_find(Pointer(fixture.target), &found);
    stats->Check(find == HOOKSELF_INLINE_OK && found == handle,
                 std::string(fixture.name) + ": find mismatch");

    HookselfInlineInfo info{};
    info.struct_size = sizeof(info);
    const int32_t info_result = hookself_inline_get_info(handle, &info);
    stats->Check(info_result == HOOKSELF_INLINE_OK,
                 std::string(fixture.name) + ": " +
                         ResultMessage("get_info", info_result));
    if (info_result == HOOKSELF_INLINE_OK) {
        stats->Check(info.state == HOOKSELF_INLINE_STATE_ACTIVE,
                     std::string(fixture.name) + ": info is not active");
        stats->Check(info.target == Address(fixture.target) &&
                             info.replacement == Address(InlineReplacement) &&
                             info.original == reinterpret_cast<uintptr_t>(original_raw),
                     std::string(fixture.name) + ": info addresses mismatch");
        stats->Check(info.patch_size == 4U && info.relocated_size >= 8U,
                     std::string(fixture.name) + ": info sizes mismatch");
        stats->Check((info.flags & (kRequiredInfoFlags |
                                   fixture.required_flags)) ==
                             (kRequiredInfoFlags | fixture.required_flags),
                     std::string(fixture.name) + ": required info flags missing");
        if ((info.flags & HOOKSELF_INLINE_INFO_F_RELOCATION_EXPANDED) != 0U) {
            ++stats->expanded_relocations;
        }
        CheckExecutableMapping(stats, info.target,
                               std::string(fixture.name) + ": target active");
        CheckExecutableMapping(stats, info.original,
                               std::string(fixture.name) + ": original active");
        if (info.bridge_address != 0U) {
            CheckExecutableMapping(stats, info.bridge_address,
                                   std::string(fixture.name) + ": bridge active");
        }
    }

    if (test_duplicate) {
        void* const published_original = original_raw;
        const HookselfInlineHandle published_handle = handle;
        const int32_t duplicate = hookself_inline_install(
                Pointer(fixture.target), Pointer(InlineReplacement), nullptr,
                &original_raw, &handle);
        stats->Check(duplicate == HOOKSELF_INLINE_E_ALREADY_INSTALLED,
                     std::string(fixture.name) +
                             ": duplicate install result mismatch");
        stats->Check(original_raw == published_original &&
                             handle == published_handle,
                     std::string(fixture.name) +
                             ": duplicate install modified active outputs");
    }

    for (uint64_t argument : kArguments) {
        stats->Check(fixture.invoke(fixture.target, argument) ==
                             argument + kReplacementDelta,
                     std::string(fixture.name) + ": replacement mismatch");
        stats->Check(fixture.invoke(original, argument) ==
                             fixture.expected(argument),
                     std::string(fixture.name) + ": original mismatch");
    }

    const int32_t remove = hookself_inline_remove(handle);
    stats->Check(remove == HOOKSELF_INLINE_OK,
                 std::string(fixture.name) + ": " +
                         ResultMessage("remove", remove));
    if (remove != HOOKSELF_INLINE_OK) {
        (void)hookself_inline_unhook(Pointer(fixture.target));
        return;
    }

    for (uint64_t argument : kArguments) {
        stats->Check(fixture.invoke(fixture.target, argument) ==
                             fixture.expected(argument),
                     std::string(fixture.name) + ": restore mismatch");
        stats->Check(fixture.invoke(original, argument) ==
                             fixture.expected(argument),
                     std::string(fixture.name) +
                             ": retained original mismatch");
    }

    info = {};
    info.struct_size = sizeof(info);
    stats->Check(hookself_inline_get_info(handle, &info) ==
                         HOOKSELF_INLINE_OK &&
                         info.state == HOOKSELF_INLINE_STATE_REMOVED,
                 std::string(fixture.name) + ": removed info mismatch");
    CheckExecutableMapping(stats, Address(fixture.target),
                           std::string(fixture.name) + ": target removed");
    CheckExecutableMapping(stats, reinterpret_cast<uintptr_t>(original_raw),
                           std::string(fixture.name) + ": original retained");
    stats->Check(hookself_inline_remove(handle) == HOOKSELF_INLINE_E_NOT_FOUND,
                 std::string(fixture.name) +
                         ": duplicate remove result mismatch");
    found = UINT64_MAX;
    stats->Check(hookself_inline_find(Pointer(fixture.target), &found) ==
                         HOOKSELF_INLINE_E_NOT_FOUND &&
                         found == HOOKSELF_INLINE_INVALID_HANDLE,
                 std::string(fixture.name) + ": removed target was found");

    if ((fixture.required_flags & HOOKSELF_INLINE_INFO_F_PATCH_AFTER_BTI) != 0U) {
        ++stats->bti_paths;
    }
    if ((fixture.required_flags & HOOKSELF_INLINE_INFO_F_PATCH_AFTER_PAC) != 0U) {
        ++stats->pac_paths;
    }
}

void TestConvenienceApi(TestStats* stats) {
    const FixtureFn target = hs_inline_fixture_convenience;
    void* original_raw = nullptr;
    const int32_t install = hookself_inline_hook(
            Pointer(target), Pointer(InlineReplacement), &original_raw);
    stats->Check(install == HOOKSELF_INLINE_OK,
                 ResultMessage("convenience hook", install));
    if (install != HOOKSELF_INLINE_OK) {
        (void)hookself_inline_unhook(Pointer(target));
        return;
    }
    const auto original = reinterpret_cast<FixtureFn>(original_raw);
    stats->Check(InvokeDirect(target, 9U) == 9U + kReplacementDelta,
                 "convenience replacement mismatch");
    stats->Check(InvokeDirect(original, 9U) == 28U,
                 "convenience original mismatch");
    const int32_t remove = hookself_inline_unhook(Pointer(target));
    stats->Check(remove == HOOKSELF_INLINE_OK,
                 ResultMessage("convenience unhook", remove));
    stats->Check(InvokeDirect(target, 9U) == 28U,
                 "convenience restore mismatch");
    stats->Check(InvokeDirect(original, 9U) == 28U,
                 "convenience retained original mismatch");
    stats->Check(hookself_inline_unhook(Pointer(target)) ==
                         HOOKSELF_INLINE_E_NOT_FOUND,
                 "convenience duplicate unhook result mismatch");
}

void TestMultipleHooks(TestStats* stats) {
    const FixtureFn first = hs_inline_fixture_multi_a;
    const FixtureFn second = hs_inline_fixture_multi_b;
    void* first_original_raw = nullptr;
    void* second_original_raw = nullptr;
    HookselfInlineHandle first_handle = HOOKSELF_INLINE_INVALID_HANDLE;
    HookselfInlineHandle second_handle = HOOKSELF_INLINE_INVALID_HANDLE;
    const int32_t first_install = hookself_inline_install(
            Pointer(first), Pointer(InlineReplacement), nullptr,
            &first_original_raw, &first_handle);
    stats->Check(first_install == HOOKSELF_INLINE_OK,
                 ResultMessage("multi first install", first_install));
    if (first_install != HOOKSELF_INLINE_OK) {
        return;
    }
    const int32_t second_install = hookself_inline_install(
            Pointer(second), Pointer(InlineReplacement), nullptr,
            &second_original_raw, &second_handle);
    stats->Check(second_install == HOOKSELF_INLINE_OK,
                 ResultMessage("multi second install", second_install));
    if (second_install != HOOKSELF_INLINE_OK) {
        (void)hookself_inline_remove(first_handle);
        return;
    }

    stats->Check(InvokeDirect(first, 1U) == 1U + kReplacementDelta &&
                         InvokeDirect(second, 2U) == 2U + kReplacementDelta,
                 "multi replacement mismatch");
    stats->Check(InvokeDirect(reinterpret_cast<FixtureFn>(first_original_raw),
                              1U) == 22U &&
                         InvokeDirect(reinterpret_cast<FixtureFn>(second_original_raw),
                                      2U) == 25U,
                 "multi original mismatch");
    stats->Check(hookself_inline_remove(first_handle) == HOOKSELF_INLINE_OK,
                 "multi first remove failed");
    stats->Check(InvokeDirect(first, 1U) == 22U &&
                         InvokeDirect(second, 2U) == 2U + kReplacementDelta,
                 "multi independent removal mismatch");
    stats->Check(hookself_inline_unhook(Pointer(second)) == HOOKSELF_INLINE_OK,
                 "multi second unhook failed");
    stats->Check(InvokeDirect(first, 1U) == 22U &&
                         InvokeDirect(second, 2U) == 25U,
                 "multi restore mismatch");
}

void TestGuardedBtiPage(TestStats* stats) {
#if defined(__aarch64__)
    if ((getauxval(AT_HWCAP2) & static_cast<unsigned long>(HWCAP2_BTI)) == 0U) {
        return;
    }
    stats->bti_guarded_supported = 1U;

    const long page_size_result = sysconf(_SC_PAGESIZE);
    stats->Check(page_size_result > 0, "guarded BTI page size unavailable");
    if (page_size_result <= 0) {
        return;
    }
    const size_t page_size = static_cast<size_t>(page_size_result);
    void* const page = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    stats->Check(page != MAP_FAILED, "guarded BTI mmap failed");
    if (page == MAP_FAILED) {
        return;
    }

    auto* const code = static_cast<uint32_t*>(page);
    code[0] = UINT32_C(0xd503245f);  // BTI C
    code[1] = UINT32_C(0x91007400);  // ADD X0, X0, #29
    code[2] = UINT32_C(0xd65f03c0);  // RET
    __builtin___clear_cache(static_cast<char*>(page),
                            static_cast<char*>(page) + 3U * sizeof(uint32_t));
    const int protect = mprotect(
            page, page_size, PROT_READ | PROT_EXEC | PROT_BTI);
    stats->Check(protect == 0, "guarded BTI mprotect failed");
    if (protect != 0) {
        (void)munmap(page, page_size);
        return;
    }

    const uintptr_t target_address = reinterpret_cast<uintptr_t>(page);
    const auto target = reinterpret_cast<FixtureFn>(target_address);
    stats->Check(MappingHasVmFlag(target_address, "bt"),
                 "guarded BTI mapping missing bt before install");
    CheckExecutableMapping(stats, target_address,
                           "guarded BTI target before install");
    stats->Check(InvokeDirect(target, 7U) == 36U,
                 "guarded BTI baseline mismatch");

    void* original_raw = nullptr;
    HookselfInlineHandle handle = HOOKSELF_INLINE_INVALID_HANDLE;
    const int32_t install = hookself_inline_install(
            page, Pointer(InlineReplacement), nullptr,
            &original_raw, &handle);
    stats->Check(install == HOOKSELF_INLINE_OK,
                 ResultMessage("guarded BTI install", install));
    if (install != HOOKSELF_INLINE_OK) {
        (void)munmap(page, page_size);
        return;
    }

    const auto original = reinterpret_cast<FixtureFn>(original_raw);
    HookselfInlineInfo info{};
    info.struct_size = sizeof(info);
    const int32_t active_info = hookself_inline_get_info(handle, &info);
    stats->Check(active_info == HOOKSELF_INLINE_OK,
                 ResultMessage("guarded BTI active info", active_info));
    if (active_info == HOOKSELF_INLINE_OK) {
        stats->Check(info.state == HOOKSELF_INLINE_STATE_ACTIVE &&
                             info.target == target_address &&
                             info.patch_address == target_address + 4U &&
                             info.original == reinterpret_cast<uintptr_t>(original_raw),
                     "guarded BTI active info mismatch");
        stats->Check((info.flags &
                      (HOOKSELF_INLINE_INFO_F_PATCH_AFTER_BTI |
                       HOOKSELF_INLINE_INFO_F_TRAMPOLINE_RETAINED)) ==
                             (HOOKSELF_INLINE_INFO_F_PATCH_AFTER_BTI |
                              HOOKSELF_INLINE_INFO_F_TRAMPOLINE_RETAINED),
                     "guarded BTI active flags mismatch");
        if (info.bridge_address != 0U) {
            stats->bti_guarded_far_bridge = 1U;
            CheckExecutableMapping(stats, info.bridge_address,
                                   "guarded BTI bridge active");
        }
    }
    stats->Check(MappingHasVmFlag(target_address, "bt"),
                 "guarded BTI mapping lost bt while active");
    CheckExecutableMapping(stats, target_address,
                           "guarded BTI target active");
    CheckExecutableMapping(stats, reinterpret_cast<uintptr_t>(original_raw),
                           "guarded BTI original active");
    stats->Check(InvokeDirect(target, 7U) == 7U + kReplacementDelta,
                 "guarded BTI replacement mismatch");
    stats->Check(InvokeDirect(original, 7U) == 36U,
                 "guarded BTI original mismatch");

    const int32_t remove = hookself_inline_remove(handle);
    stats->Check(remove == HOOKSELF_INLINE_OK,
                 ResultMessage("guarded BTI remove", remove));
    if (remove != HOOKSELF_INLINE_OK) {
        const int32_t cleanup = hookself_inline_unhook(page);
        stats->Check(cleanup == HOOKSELF_INLINE_OK,
                     ResultMessage("guarded BTI cleanup", cleanup));
        if (cleanup != HOOKSELF_INLINE_OK) {
            return;
        }
    }

    info = {};
    info.struct_size = sizeof(info);
    const int32_t removed_info = hookself_inline_get_info(handle, &info);
    stats->Check(removed_info == HOOKSELF_INLINE_OK &&
                         info.state == HOOKSELF_INLINE_STATE_REMOVED,
                 "guarded BTI removed info mismatch");
    stats->Check(MappingHasVmFlag(target_address, "bt"),
                 "guarded BTI mapping lost bt after remove");
    CheckExecutableMapping(stats, target_address,
                           "guarded BTI target removed");
    stats->Check(InvokeDirect(target, 7U) == 36U,
                 "guarded BTI restore mismatch");
    stats->Check(InvokeDirect(original, 7U) == 36U,
                 "guarded BTI retained original mismatch");

    ++stats->bti_guarded_paths;
    stats->Check(munmap(page, page_size) == 0,
                 "guarded BTI munmap failed");
#else
    (void)stats;
#endif
}

void TestConcurrentInstallRemove(TestStats* stats) {
    constexpr uint32_t kThreads = 4U;
    constexpr uint32_t kCycles = 96U;
    const FixtureFn target = hs_inline_fixture_concurrent;
    std::atomic<bool> running{true};
    std::atomic<uint64_t> calls{0U};
    std::atomic<uint64_t> bad_results{0U};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (uint32_t index = 0; index < kThreads; ++index) {
        workers.emplace_back([&, index]() {
            uint64_t argument = static_cast<uint64_t>(index + 1U);
            while (running.load(std::memory_order_acquire)) {
                const uint64_t value = InvokeDirect(target, argument);
                if (value != argument + 3U &&
                    value != argument + kReplacementDelta) {
                    bad_results.fetch_add(1U, std::memory_order_relaxed);
                }
                calls.fetch_add(1U, std::memory_order_relaxed);
                argument = argument == 127U ? 1U : argument + 1U;
            }
        });
    }

    FixtureFn retained_original = nullptr;
    uint32_t completed_cycles = 0;
    for (uint32_t cycle = 0; cycle < kCycles; ++cycle) {
        void* original_raw = nullptr;
        HookselfInlineHandle handle = HOOKSELF_INLINE_INVALID_HANDLE;
        const int32_t install = hookself_inline_install(
                Pointer(target), Pointer(InlineReplacement), nullptr,
                &original_raw, &handle);
        stats->Check(install == HOOKSELF_INLINE_OK,
                     ResultMessage("concurrent install", install));
        if (install != HOOKSELF_INLINE_OK) {
            break;
        }
        const auto original = reinterpret_cast<FixtureFn>(original_raw);
        if (retained_original == nullptr) {
            retained_original = original;
        }
        stats->Check(InvokeDirect(original, cycle) == cycle + 3U,
                     "concurrent original mismatch");
        for (uint32_t spin = 0; spin < 4U; ++spin) {
            std::this_thread::yield();
        }
        const int32_t remove = hookself_inline_remove(handle);
        stats->Check(remove == HOOKSELF_INLINE_OK,
                     ResultMessage("concurrent remove", remove));
        if (remove != HOOKSELF_INLINE_OK) {
            (void)hookself_inline_unhook(Pointer(target));
            break;
        }
        ++completed_cycles;
        for (uint32_t spin = 0; spin < 4U; ++spin) {
            std::this_thread::yield();
        }
    }

    running.store(false, std::memory_order_release);
    for (std::thread& worker : workers) {
        worker.join();
    }
    stats->concurrent_calls = calls.load(std::memory_order_relaxed);
    stats->Check(completed_cycles == kCycles,
                 "concurrent cycle count mismatch");
    stats->Check(stats->concurrent_calls > 0U,
                 "concurrent workers made no calls");
    stats->Check(bad_results.load(std::memory_order_relaxed) == 0U,
                 "concurrent target returned a torn result");
    stats->Check(InvokeDirect(target, 11U) == 14U,
                 "concurrent target was not restored");
    stats->Check(retained_original != nullptr &&
                         InvokeDirect(retained_original, 11U) == 14U,
                 "old concurrent original was not retained");
    CheckExecutableMapping(stats, Address(target),
                           "concurrent target removed");
    if (retained_original != nullptr) {
        CheckExecutableMapping(stats, Address(retained_original),
                               "concurrent original retained");
    }
}

std::string EscapeJson(const std::string& value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (char character : value) {
        if (character == '\\' || character == '"') {
            escaped.push_back('\\');
        }
        if (character == '\n' || character == '\r') {
            escaped.push_back(' ');
        } else {
            escaped.push_back(character);
        }
    }
    return escaped;
}

std::string RunInlineHookSelfTest() {
    TestStats stats{};
    TestApiContract(&stats);
    TestUnsupportedRelocation(&stats);

    constexpr uint32_t kBtiFlag = HOOKSELF_INLINE_INFO_F_PATCH_AFTER_BTI;
    constexpr uint32_t kPacFlag = HOOKSELF_INLINE_INFO_F_PATCH_AFTER_PAC |
            HOOKSELF_INLINE_INFO_F_NEAR_BRIDGE;
    const FixtureCase fixtures[] = {
            {"plain", hs_inline_fixture_plain, InvokeDirect, ExpectedPlain, 0U},
            {"adr", hs_inline_fixture_adr, InvokeDirect, ExpectedAdr, 0U},
            {"adrp", hs_inline_fixture_adrp, InvokeDirect, ExpectedAdrp, 0U},
            {"literal_w", hs_inline_fixture_literal_w, InvokeDirect,
             ExpectedLiteralW, 0U},
            {"literal_x", hs_inline_fixture_literal_x, InvokeDirect,
             ExpectedLiteralX, 0U},
            {"ldrsw", hs_inline_fixture_ldrsw, InvokeDirect, ExpectedLdrsw, 0U},
            {"literal_s", hs_inline_fixture_literal_s, InvokeDirect,
             ExpectedLiteralS, 0U},
            {"literal_d", hs_inline_fixture_literal_d, InvokeDirect,
             ExpectedLiteralD, 0U},
            {"literal_q", hs_inline_fixture_literal_q, InvokeDirect,
             ExpectedLiteralQ, 0U},
            {"prfm", hs_inline_fixture_prfm, InvokeDirect, ExpectedPrfm, 0U},
            {"b", hs_inline_fixture_b, InvokeDirect, ExpectedB, 0U},
            {"bl", hs_inline_fixture_bl, InvokeBl, ExpectedBl, 0U},
            {"b_cond", hs_inline_fixture_bcond, InvokeBcond, ExpectedBcond, 0U},
            {"cbz", hs_inline_fixture_cbz, InvokeDirect, ExpectedCbz, 0U},
            {"cbnz", hs_inline_fixture_cbnz, InvokeDirect, ExpectedCbnz, 0U},
            {"tbz", hs_inline_fixture_tbz, InvokeDirect, ExpectedTbz, 0U},
            {"tbnz", hs_inline_fixture_tbnz, InvokeDirect, ExpectedTbnz, 0U},
            {"bti", hs_inline_fixture_bti, InvokeDirect, ExpectedBti, kBtiFlag},
            {"paciasp", hs_inline_fixture_paciasp, InvokeDirect,
             ExpectedPaciasp, kPacFlag},
            {"pacibsp", hs_inline_fixture_pacibsp, InvokeDirect,
             ExpectedPacibsp, kPacFlag},
    };
    for (size_t index = 0; index < sizeof(fixtures) / sizeof(fixtures[0]);
         ++index) {
        TestFixture(&stats, fixtures[index], index == 0U);
    }

    TestConvenienceApi(&stats);
    TestMultipleHooks(&stats);
    TestGuardedBtiPage(&stats);
    TestConcurrentInstallRemove(&stats);
    stats.Check(stats.rwx_violations == 0U,
                "one or more hook mappings retained RWX permissions");
    stats.Check(stats.bti_paths == 1U, "BTI path count mismatch");
    stats.Check(stats.pac_paths == 2U, "PAC path count mismatch");

    std::ostringstream report;
    report << "HOOKSELF_INLINE_RESULT {\"verdict\":\""
           << (stats.failures == 0U ? "PASS" : "FAILED")
           << "\",\"version\":1,\"checks\":" << stats.checks
           << ",\"failures\":" << stats.failures
           << ",\"fixtures\":" << stats.fixtures
           << ",\"expanded_relocations\":" << stats.expanded_relocations
           << ",\"bti_paths\":" << stats.bti_paths
           << ",\"bti_guarded_supported\":"
           << stats.bti_guarded_supported
           << ",\"bti_guarded_paths\":" << stats.bti_guarded_paths
           << ",\"bti_guarded_far_bridge\":"
           << stats.bti_guarded_far_bridge
           << ",\"pac_paths\":" << stats.pac_paths
           << ",\"unsupported_relocations\":"
           << stats.unsupported_relocations
           << ",\"rwx_violations\":" << stats.rwx_violations
           << ",\"concurrent_calls\":" << stats.concurrent_calls
           << ",\"concurrent_cycles\":96"
           << ",\"first_failure\":\"" << EscapeJson(stats.first_failure)
           << "\"}";
    return report.str();
}

}  // namespace

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_runInlineHookSelfTest(
        JNIEnv* env, jclass) {
    try {
        const std::string report = RunInlineHookSelfTest();
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_INLINE_RESULT {\"verdict\":\"INTERNAL_ERROR\","
                "\"version\":1,\"checks\":0,\"failures\":1,"
                "\"fixtures\":0,\"expanded_relocations\":0,"
                "\"bti_paths\":0,\"bti_guarded_supported\":0,"
                "\"bti_guarded_paths\":0,\"bti_guarded_far_bridge\":0,"
                "\"pac_paths\":0,\"unsupported_relocations\":0,"
                "\"rwx_violations\":0,"
                "\"concurrent_calls\":0,\"concurrent_cycles\":0,"
                "\"first_failure\":\"native exception\"}");
    }
}
