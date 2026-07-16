#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

#include "hookself/inline_hook.h"
#include "inline_hook/internal/arm64_encoding.h"
#include "inline_hook/internal/arm64_relocator.h"
#include "inline_hook/internal/memory.h"

namespace arm64 = hookself::inline_hook::arm64;
namespace memory = hookself::inline_hook::internal;

namespace {

int g_failures = 0;

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fprintf(stderr, "CHECK failed at line %d: %s\n", __LINE__,       \
                    #expression);                                             \
            ++g_failures;                                                     \
        }                                                                     \
    } while (false)

uint32_t Read32(const uint8_t* bytes, size_t offset) {
    uint32_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

uint64_t Read64(const uint8_t* bytes, size_t offset) {
    uint64_t value = 0;
    memcpy(&value, bytes + offset, sizeof(value));
    return value;
}

void TestArchitecturalConstants() {
    CHECK(arm64::kBti == 0xd503241fU);
    CHECK(arm64::kBtiC == 0xd503245fU);
    CHECK(arm64::kBtiJ == 0xd503249fU);
    CHECK(arm64::kBtiJc == 0xd50324dfU);
    CHECK(arm64::kPaciasp == 0xd503233fU);
    CHECK(arm64::kPacibsp == 0xd503237fU);
    CHECK(arm64::kAutiasp == 0xd50323bfU);
    CHECK(arm64::kAutibsp == 0xd50323ffU);
    CHECK(arm64::kBrX17 == 0xd61f0220U);
    CHECK(arm64::kBlrX17 == 0xd63f0220U);
    CHECK(arm64::kStrX17PreIndexSpMinus16 == 0xf81f0ff1U);
    CHECK(arm64::kLdrX17PostIndexSpPlus16 == 0xf84107f1U);

    CHECK(arm64::IsBti(arm64::kBti));
    CHECK(arm64::IsBti(arm64::kBtiC));
    CHECK(arm64::IsBti(arm64::kBtiJ));
    CHECK(arm64::IsBti(arm64::kBtiJc));
    CHECK(!arm64::IsBti(arm64::kNop));

    uint32_t authenticate = 0;
    CHECK(arm64::IsPacEntry(arm64::kPaciasp, &authenticate));
    CHECK(authenticate == arm64::kAutiasp);
    CHECK(arm64::IsPacEntry(arm64::kPacibsp, &authenticate));
    CHECK(authenticate == arm64::kAutibsp);
    CHECK(!arm64::IsPacEntry(arm64::kAutiasp, &authenticate));

    constexpr uint32_t exception_generation[] = {
            0xd4000001U,  // SVC #0
            0xd4000022U,  // HVC #1
            0xd4000043U,  // SMC #2
            0xd4200060U,  // BRK #3
            0xd4400080U,  // HLT #4
            0xd4a00001U,  // DCPS1 #0
    };
    for (uint32_t instruction : exception_generation) {
        CHECK(arm64::IsExceptionGeneration(instruction));
        uint8_t output[16];
        memset(output, 0xa5, sizeof(output));
        arm64::RelocationRequest request{};
        request.instruction = instruction;
        request.source_pc = 0x10000000U;
        request.continuation = request.source_pc + 4U;
        request.output = output;
        request.output_capacity = sizeof(output);
        request.output_address = 0x11000000U;
        arm64::RelocationResult result{1U, 1U, 1U, 1U};
        CHECK(arm64::RelocateOneAndContinue(request, &result) ==
              arm64::RelocationStatus::kUnsupported);
        CHECK(result.code_size == 0U && result.total_size == 0U &&
              result.expanded == 0U && result.uses_x17 == 0U);
        for (uint8_t byte : output) {
            CHECK(byte == 0xa5U);
        }
    }
    CHECK(!arm64::IsExceptionGeneration(arm64::kNop));
    CHECK(!arm64::IsExceptionGeneration(0x14000000U));
}

void TestLiteralMemoryLoads() {
    struct Case {
        uint32_t literal;
        uint32_t expected;
    };
    constexpr Case cases[] = {
            {0x18000003U, 0xb94000e3U},  // LDR W3 -> LDR W3, [X7]
            {0x58000003U, 0xf94000e3U},  // LDR X3 -> LDR X3, [X7]
            {0x98000003U, 0xb98000e3U},  // LDRSW X3 -> LDRSW X3, [X7]
            {0xd8000000U, 0xf98000e0U},  // PRFM #0 -> PRFM #0, [X7]
            {0x1c000003U, 0xbd4000e3U},  // LDR S3 -> LDR S3, [X7]
            {0x5c000003U, 0xfd4000e3U},  // LDR D3 -> LDR D3, [X7]
            {0x9c000003U, 0x3dc000e3U},  // LDR Q3 -> LDR Q3, [X7]
    };
    for (const Case& test : cases) {
        uint32_t encoded = 0;
        CHECK(arm64::DecodeKind(test.literal) ==
              arm64::InstructionKind::kLiteralLoad);
        CHECK(arm64::EncodeLiteralMemoryLoad(test.literal, 7U, &encoded));
        CHECK(encoded == test.expected);
    }

    uint32_t encoded = 0;
    CHECK(!arm64::EncodeLiteralMemoryLoad(0xdc000003U, 7U, &encoded));
    CHECK(!arm64::EncodeLiteralMemoryLoad(0x58000003U, 32U, &encoded));
}

void TestPcRelativeBoundaries() {
    constexpr uintptr_t pc = UINT64_C(0x200000000);
    uint32_t encoded = 0;

    CHECK(arm64::EncodeBranch(pc, pc + 0x07fffffcU, false, &encoded));
    CHECK(encoded == 0x15ffffffU);
    CHECK(arm64::DecodePcRelativeTarget(encoded, pc) ==
          pc + 0x07fffffcU);
    CHECK(arm64::EncodeBranch(pc, pc - 0x08000000U, true, &encoded));
    CHECK(encoded == 0x96000000U);
    CHECK(arm64::DecodePcRelativeTarget(encoded, pc) ==
          pc - 0x08000000U);
    CHECK(!arm64::EncodeBranch(pc, pc + 0x08000000U, false, &encoded));
    CHECK(!arm64::EncodeBranch(pc, pc - 0x08000004U, false, &encoded));
    CHECK(!arm64::EncodeBranch(pc, pc + 2U, false, &encoded));

    CHECK(arm64::EncodePcRelative(0x54000001U, pc, pc + 0x000ffffcU,
                                  &encoded));
    CHECK(encoded == 0x547fffe1U);
    CHECK(arm64::EncodePcRelative(0x54000001U, pc, pc - 0x00100000U,
                                  &encoded));
    CHECK(encoded == 0x54800001U);
    CHECK(!arm64::EncodePcRelative(0x54000001U, pc,
                                   pc + 0x00100000U, &encoded));
    CHECK(!arm64::EncodePcRelative(0x54000001U, pc,
                                   pc - 0x00100004U, &encoded));

    CHECK(arm64::DecodeKind(0x54000010U) ==
          arm64::InstructionKind::kBCond);
    CHECK(arm64::EncodePcRelative(0x54000010U, pc, pc + 0x000ffffcU,
                                  &encoded));
    CHECK(encoded == 0x547ffff0U);

    CHECK(arm64::EncodePcRelative(0xb4000003U, pc, pc + 0x000ffffcU,
                                  &encoded));
    CHECK(encoded == 0xb47fffe3U);
    CHECK(arm64::EncodePcRelative(0xb4000003U, pc, pc - 0x00100000U,
                                  &encoded));
    CHECK(encoded == 0xb4800003U);

    CHECK(arm64::EncodePcRelative(0xb6f80005U, pc, pc + 0x00007ffcU,
                                  &encoded));
    CHECK(encoded == 0xb6fbffe5U);
    CHECK(arm64::EncodePcRelative(0xb6f80005U, pc, pc - 0x00008000U,
                                  &encoded));
    CHECK(encoded == 0xb6fc0005U);
    CHECK(!arm64::EncodePcRelative(0xb6f80005U, pc, pc + 0x00008000U,
                                   &encoded));

    CHECK(arm64::EncodePcRelative(0x10000007U, pc, pc + 0x000fffffU,
                                  &encoded));
    CHECK(encoded == 0x707fffe7U);
    CHECK(arm64::DecodePcRelativeTarget(encoded, pc) ==
          pc + 0x000fffffU);
    CHECK(arm64::EncodePcRelative(0x10000007U, pc, pc - 0x00100000U,
                                  &encoded));
    CHECK(encoded == 0x10800007U);
    CHECK(arm64::DecodePcRelativeTarget(encoded, pc) ==
          pc - 0x00100000U);
    CHECK(!arm64::EncodePcRelative(0x10000007U, pc,
                                   pc + 0x00100000U, &encoded));

    constexpr uintptr_t adrp_pc = UINT64_C(0x200000123);
    constexpr uintptr_t source_page = adrp_pc & ~uintptr_t{0xfffU};
    CHECK(arm64::EncodePcRelative(0x90000009U, adrp_pc,
                                  source_page + UINT64_C(0xfffff000),
                                  &encoded));
    CHECK(encoded == 0xf07fffe9U);
    CHECK(arm64::DecodePcRelativeTarget(encoded, adrp_pc) ==
          source_page + UINT64_C(0xfffff000));
    CHECK(arm64::EncodePcRelative(0x90000009U, adrp_pc,
                                  source_page - UINT64_C(0x100000000),
                                  &encoded));
    CHECK(encoded == 0x90800009U);
    CHECK(arm64::DecodePcRelativeTarget(encoded, adrp_pc) ==
          source_page - UINT64_C(0x100000000));
    CHECK(!arm64::EncodePcRelative(0x90000009U, adrp_pc,
                                   source_page + UINT64_C(0x100000000),
                                   &encoded));
    CHECK(!arm64::EncodePcRelative(0x90000009U, adrp_pc,
                                   source_page - UINT64_C(0x100001000),
                                   &encoded));
}

void TestWriterAbsoluteAlignment() {
    uint8_t bytes[16]{};
    arm64::CodeWriter unaligned(bytes, sizeof(bytes), 0x1004U);
    CHECK(unaligned.Align8());
    CHECK(unaligned.size() == 4U);
    CHECK(unaligned.address() == 0x1008U);
    CHECK(Read32(bytes, 0U) == arm64::kNop);

    memset(bytes, 0, sizeof(bytes));
    arm64::CodeWriter aligned(bytes, sizeof(bytes), 0x1000U);
    CHECK(aligned.Align8());
    CHECK(aligned.size() == 0U);

    arm64::CodeWriter becomes_aligned(bytes, sizeof(bytes), 0x1004U);
    CHECK(becomes_aligned.Emit32(arm64::kNop));
    CHECK(becomes_aligned.Align8());
    CHECK(becomes_aligned.size() == 4U);
}

void TestAtomicPatchConflict() {
    const size_t page_size = memory::PageSize();
    void* const page = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(page != MAP_FAILED);
    if (page == MAP_FAILED) {
        return;
    }
    auto* const instruction = static_cast<uint32_t*>(page);
    *instruction = arm64::kNop;
    CHECK(mprotect(page, page_size, PROT_READ | PROT_EXEC) == 0);

    constexpr uint32_t kRet = 0xd65f03c0U;
    CHECK(memory::PatchExecutableInstruction(
                  reinterpret_cast<uintptr_t>(page), kRet, arm64::kBrX17) ==
          HOOKSELF_INLINE_E_CONFLICT);
    CHECK(*instruction == arm64::kNop);

    CHECK(memory::PatchExecutableInstruction(
                  reinterpret_cast<uintptr_t>(page), arm64::kNop, kRet) ==
          HOOKSELF_INLINE_OK);
    CHECK(*instruction == kRet);
    CHECK(memory::PatchExecutableInstruction(
                  reinterpret_cast<uintptr_t>(page), kRet, arm64::kNop) ==
          HOOKSELF_INLINE_OK);
    CHECK(*instruction == arm64::kNop);
    CHECK(munmap(page, page_size) == 0);
}

arm64::RelocationRequest MakeRequest(uint32_t instruction,
                                     uintptr_t source_pc,
                                     uintptr_t output_address,
                                     uint8_t* output,
                                     size_t output_capacity) {
    arm64::RelocationRequest request{};
    request.instruction = instruction;
    request.source_pc = source_pc;
    request.continuation = source_pc + 4U;
    request.output = output;
    request.output_capacity = output_capacity;
    request.output_address = output_address;
    return request;
}

void TestRegisterBranchWithLinkRelocation() {
    constexpr uint32_t with_link[] = {
            0xd63f0000U, 0xd63f0220U, 0xd63f03c0U,  // BLR X0/X17/X30
            0xd73f0801U, 0xd73f0a22U, 0xd73f0bddU,  // BLRAA
            0xd73f0c64U, 0xd73f0e2fU, 0xd73f0fddU,  // BLRAB
            0xd63f081fU, 0xd63f0a3fU, 0xd63f0bdfU,  // BLRAAZ
            0xd63f0c1fU, 0xd63f0e3fU, 0xd63f0fdfU,  // BLRABZ
    };
    for (uint32_t instruction : with_link) {
        CHECK(arm64::IsRegisterBranchWithLink(instruction));

        uint8_t output[64];
        memset(output, 0xa5, sizeof(output));
        arm64::RelocationRequest request = MakeRequest(
                instruction, 0x10000000U, 0x14000000U,
                output, sizeof(output));
        arm64::RelocationResult result{11U, 22U, 1U, 1U};
        CHECK(arm64::RelocateOneAndContinue(request, &result) ==
              arm64::RelocationStatus::kUnsupported);
        CHECK(result.code_size == 0U);
        CHECK(result.total_size == 0U);
        CHECK(result.expanded == 0U);
        CHECK(result.uses_x17 == 0U);
        for (uint8_t byte : output) {
            CHECK(byte == 0xa5U);
        }
    }

    constexpr uint32_t without_link[] = {
            0xd61f0000U, 0xd61f0220U, 0xd61f03c0U,  // BR X0/X17/X30
            0xd71f0801U, 0xd71f0a22U,               // BRAA
            0xd71f0c64U, 0xd71f0e2fU,               // BRAB
            0xd61f081fU, 0xd61f0a3fU,               // BRAAZ
            0xd61f0c1fU, 0xd61f0e3fU,               // BRABZ
            0xd65f03c0U, 0xd65f0220U,               // RET X30/X17
            0xd65f0bffU, 0xd65f0fffU,               // RETAA/RETAB
            0x94000000U,                             // BL immediate
    };
    for (uint32_t instruction : without_link) {
        CHECK(!arm64::IsRegisterBranchWithLink(instruction));
    }
}

void TestFarLiteralRelocations() {
    struct Case {
        uint32_t literal;
        uint32_t expected_memory_load;
        uint32_t address_register;
        uint32_t uses_x17;
    };
    constexpr Case cases[] = {
            {0x18000003U, 0xb9400063U, 3U, 0U},
            {0x58000003U, 0xf9400063U, 3U, 0U},
            {0x98000003U, 0xb9800063U, 3U, 0U},
            {0x1800001fU, 0xb940023fU, 17U, 1U},
            {0x5800001fU, 0xf940023fU, 17U, 1U},
            {0x9800001fU, 0xb980023fU, 17U, 1U},
            {0xd8000000U, 0xf9800220U, 17U, 1U},
            {0x1c000003U, 0xbd400223U, 17U, 1U},
            {0x5c000003U, 0xfd400223U, 17U, 1U},
            {0x9c000003U, 0x3dc00223U, 17U, 1U},
    };
    constexpr uintptr_t source_pc = 0x10000000U;
    constexpr uintptr_t literal_target = source_pc + 0x100U;
    constexpr uintptr_t output_address = 0x14000004U;

    for (const Case& test : cases) {
        uint32_t original = 0;
        CHECK(arm64::EncodePcRelative(test.literal, source_pc,
                                      literal_target, &original));
        uint8_t output[64]{};
        arm64::RelocationRequest request = MakeRequest(
                original, source_pc, output_address, output, sizeof(output));
        arm64::RelocationResult result{};
        CHECK(arm64::RelocateOneAndContinue(request, &result) ==
              arm64::RelocationStatus::kOk);
        const bool saves_x17 = test.uses_x17 != 0U;
        const size_t address_load_offset = saves_x17 ? 4U : 0U;
        const size_t memory_load_offset = saves_x17 ? 8U : 4U;
        const size_t continuation_offset = saves_x17 ? 16U : 8U;
        const size_t literal_offset = saves_x17 ? 20U : 12U;
        CHECK(result.code_size == (saves_x17 ? 20U : 12U));
        CHECK(result.total_size == (saves_x17 ? 28U : 20U));
        CHECK(result.expanded == 1U);
        CHECK(result.uses_x17 == test.uses_x17);
        if (saves_x17) {
            CHECK(Read32(output, 0U) ==
                  arm64::kStrX17PreIndexSpMinus16);
            CHECK(Read32(output, 12U) ==
                  arm64::kLdrX17PostIndexSpPlus16);
        }
        CHECK(Read32(output, memory_load_offset) ==
              test.expected_memory_load);
        const uintptr_t address_load_pc =
                output_address + address_load_offset;
        CHECK((arm64::DecodePcRelativeTarget(
                       Read32(output, address_load_offset),
                       address_load_pc) &
               7U) == 0U);
        CHECK(arm64::DecodePcRelativeTarget(
                      Read32(output, address_load_offset),
                      address_load_pc) ==
              output_address + literal_offset);
        CHECK((Read32(output, address_load_offset) & 0x1fU) ==
              test.address_register);
        CHECK(arm64::DecodeKind(Read32(output, continuation_offset)) ==
              arm64::InstructionKind::kB);
        CHECK(arm64::DecodePcRelativeTarget(
                      Read32(output, continuation_offset),
                      output_address + continuation_offset) ==
              source_pc + 4U);
        CHECK(Read64(output, literal_offset) == literal_target);
    }
}

void TestLiteralOverlapRanges() {
    constexpr uintptr_t target = 0x10010000U;
    constexpr uintptr_t output_address = 0x10080004U;
    struct Case {
        uint32_t literal;
        uintptr_t source_pc;
        uintptr_t literal_address;
        size_t overwritten_size;
        bool unsupported;
    };
    constexpr Case cases[] = {
            // Four-byte reads ending exactly at the patch are adjacent.
            {0x18000003U, target, target - 4U, 4U, false},  // LDR W
            {0x1c000003U, target, target - 4U, 4U, false},  // LDR S
            {0x98000003U, target, target - 4U, 4U, false},  // LDRSW

            // Eight-byte reads beginning at patch-4 overlap by four bytes.
            {0x58000003U, target, target - 4U, 4U, true},   // LDR X
            {0x5c000003U, target, target - 4U, 4U, true},   // LDR D
            {0x58000003U, target, target - 8U, 4U, false},
            {0x5c000003U, target, target + 4U, 4U, false},

            // A 16-byte Q read reaches the patch from all three positions.
            {0x9c000003U, target, target - 12U, 4U, true},
            {0x9c000003U, target, target - 8U, 4U, true},
            {0x9c000003U, target, target - 4U, 4U, true},
            {0x9c000003U, target, target - 16U, 4U, false},
            {0x9c000003U, target, target + 4U, 4U, false},

            // BTI/PAC entry layouts relocate the second instruction at +4.
            {0x58000003U, target + 4U, target, 8U, true},   // BTI + LDR X
            {0x5c000003U, target + 4U, target, 8U, true},   // PAC + LDR D
            {0x9c000003U, target + 4U, target - 4U, 8U, true},

            // PRFM is a hint and does not architecturally read data bytes.
            {0xd8000000U, target, target, 4U, false},
    };

    for (const Case& test : cases) {
        uint32_t original = 0;
        CHECK(arm64::EncodePcRelative(test.literal, test.source_pc,
                                      test.literal_address, &original));
        uint8_t output[64];
        memset(output, 0xa5, sizeof(output));
        arm64::RelocationRequest request = MakeRequest(
                original, test.source_pc, output_address,
                output, sizeof(output));
        request.overwritten_start = target;
        request.overwritten_size = test.overwritten_size;
        arm64::RelocationResult result{11U, 22U, 1U, 1U};
        const arm64::RelocationStatus status =
                arm64::RelocateOneAndContinue(request, &result);
        if (test.unsupported) {
            CHECK(status == arm64::RelocationStatus::kUnsupported);
            CHECK(result.code_size == 0U);
            CHECK(result.total_size == 0U);
            CHECK(result.expanded == 0U);
            CHECK(result.uses_x17 == 0U);
            for (uint8_t byte : output) {
                CHECK(byte == 0xa5U);
            }
        } else {
            CHECK(status == arm64::RelocationStatus::kOk);
            CHECK(result.code_size != 0U);
        }
    }
}

void TestFarAdrAlignment() {
    constexpr uintptr_t source_pc = 0x10000000U;
    constexpr uintptr_t adr_target = source_pc + 0x1000U;
    constexpr uintptr_t output_address = 0x14000004U;
    uint32_t original = 0;
    CHECK(arm64::EncodePcRelative(0x10000005U, source_pc, adr_target,
                                  &original));

    uint8_t output[64]{};
    arm64::RelocationRequest request = MakeRequest(
            original, source_pc, output_address, output, sizeof(output));
    arm64::RelocationResult result{};
    CHECK(arm64::RelocateOneAndContinue(request, &result) ==
          arm64::RelocationStatus::kOk);
    CHECK(result.code_size == 8U);
    CHECK(result.total_size == 20U);
    CHECK(Read32(output, 8U) == arm64::kNop);
    CHECK(arm64::DecodePcRelativeTarget(Read32(output, 0U),
                                        output_address) ==
          output_address + 12U);
    CHECK(((output_address + 12U) & 7U) == 0U);
    CHECK(Read64(output, 12U) == adr_target);
}

void TestBlRelocation() {
    constexpr uintptr_t source_pc = 0x10000000U;
    constexpr uintptr_t callee = source_pc + 0x1000U;
    constexpr uintptr_t output_address = 0x14000004U;
    uint32_t original = 0;
    CHECK(arm64::EncodePcRelative(0x94000000U, source_pc, callee,
                                  &original));

    uint8_t output[64]{};
    arm64::RelocationRequest request = MakeRequest(
            original, source_pc, output_address, output, sizeof(output));
    arm64::RelocationResult result{};
    CHECK(arm64::RelocateOneAndContinue(request, &result) ==
          arm64::RelocationStatus::kOk);
    CHECK(result.code_size == 8U);
    CHECK(result.total_size == 20U);
    CHECK(result.expanded == 1U);
    CHECK(result.uses_x17 == 0U);

    CHECK(arm64::DecodeKind(Read32(output, 0U)) ==
          arm64::InstructionKind::kLiteralLoad);
    CHECK((Read32(output, 0U) & 0x1fU) == 30U);
    CHECK(arm64::DecodePcRelativeTarget(Read32(output, 0U),
                                        output_address) ==
          output_address + 12U);
    CHECK(Read64(output, 12U) == source_pc + 4U);

    CHECK(arm64::DecodeKind(Read32(output, 4U)) ==
          arm64::InstructionKind::kB);
    CHECK(arm64::DecodePcRelativeTarget(Read32(output, 4U),
                                        output_address + 4U) == callee);
    CHECK(Read32(output, 8U) == arm64::kNop);
}

void TestConditionalRelocations() {
    constexpr uintptr_t source_pc = 0x10000000U;
    constexpr uintptr_t target = source_pc + 0x80000U;
    constexpr uintptr_t output_address = source_pc + 0x200000U;

    constexpr uint32_t always_conditions[] = {
            0x5400000eU,  // B.AL
            0x5400000fU,  // B.NV (also always in A64)
            0x5400001eU,  // BC.AL
            0x5400001fU,  // BC.NV
    };
    for (uint32_t instruction : always_conditions) {
        uint32_t original = 0;
        CHECK(arm64::EncodePcRelative(instruction, source_pc, target,
                                      &original));
        uint8_t output[64]{};
        arm64::RelocationRequest request = MakeRequest(
                original, source_pc, output_address, output, sizeof(output));
        arm64::RelocationResult result{};
        CHECK(arm64::RelocateOneAndContinue(request, &result) ==
              arm64::RelocationStatus::kOk);
        CHECK(result.code_size == 4U);
        CHECK(result.total_size == 4U);
        CHECK(arm64::DecodeKind(Read32(output, 0U)) ==
              arm64::InstructionKind::kB);
        CHECK(arm64::DecodePcRelativeTarget(Read32(output, 0U),
                                            output_address) == target);
    }

    uint32_t original = 0;
    CHECK(arm64::EncodePcRelative(0x54000010U, source_pc, target, &original));
    uint8_t output[64]{};
    arm64::RelocationRequest request = MakeRequest(
            original, source_pc, output_address, output, sizeof(output));
    arm64::RelocationResult result{};
    CHECK(arm64::RelocateOneAndContinue(request, &result) ==
          arm64::RelocationStatus::kOk);
    CHECK(result.code_size == 12U);
    CHECK(result.expanded == 1U);
    CHECK(arm64::DecodeKind(Read32(output, 0U)) ==
          arm64::InstructionKind::kBCond);
    CHECK((Read32(output, 0U) & 0x1fU) == 0x11U);
    CHECK(arm64::DecodePcRelativeTarget(Read32(output, 0U),
                                        output_address) ==
          output_address + 8U);
    CHECK(arm64::DecodePcRelativeTarget(Read32(output, 4U),
                                        output_address + 4U) == target);
}

}  // namespace

int main() {
    TestArchitecturalConstants();
    TestLiteralMemoryLoads();
    TestPcRelativeBoundaries();
    TestWriterAbsoluteAlignment();
    TestAtomicPatchConflict();
    TestRegisterBranchWithLinkRelocation();
    TestFarLiteralRelocations();
    TestLiteralOverlapRanges();
    TestFarAdrAlignment();
    TestBlRelocation();
    TestConditionalRelocations();
    if (g_failures != 0) {
        fprintf(stderr, "arm64 encoding/relocator: %d failure(s)\n",
                g_failures);
        return 1;
    }
    puts("arm64 encoding/relocator: all checks passed");
    return 0;
}
