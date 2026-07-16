#ifndef HOOKSELF_INLINE_ARM64_ENCODING_H
#define HOOKSELF_INLINE_ARM64_ENCODING_H

#include <stddef.h>
#include <stdint.h>

namespace hookself::inline_hook::arm64 {

constexpr uint32_t kNop = 0xd503201fU;
constexpr uint32_t kBti = 0xd503241fU;
constexpr uint32_t kBtiC = 0xd503245fU;
constexpr uint32_t kBtiJ = 0xd503249fU;
constexpr uint32_t kBtiJc = 0xd50324dfU;
constexpr uint32_t kPaciasp = 0xd503233fU;
constexpr uint32_t kPacibsp = 0xd503237fU;
constexpr uint32_t kAutiasp = 0xd50323bfU;
constexpr uint32_t kAutibsp = 0xd50323ffU;
constexpr uint32_t kBrX17 = 0xd61f0220U;
constexpr uint32_t kBlrX17 = 0xd63f0220U;
constexpr uint32_t kStrX17PreIndexSpMinus16 = 0xf81f0ff1U;
constexpr uint32_t kLdrX17PostIndexSpPlus16 = 0xf84107f1U;
constexpr uint64_t kBranchRange = UINT64_C(1) << 27;

enum class InstructionKind {
    kOther,
    kB,
    kBl,
    kBCond,
    kCompareBranch,
    kTestBranch,
    kAdr,
    kAdrp,
    kLiteralLoad,
};

class CodeWriter {
public:
    CodeWriter(uint8_t* buffer, size_t capacity, uintptr_t address) noexcept;

    bool Emit32(uint32_t value) noexcept;
    bool Emit64(uint64_t value) noexcept;
    bool Align8() noexcept;
    bool Patch32(size_t offset, uint32_t value) noexcept;

    size_t size() const noexcept { return size_; }
    uintptr_t address() const noexcept { return address_ + size_; }
    uintptr_t address_at(size_t offset) const noexcept {
        return address_ + offset;
    }
    uint8_t* data() const noexcept { return buffer_; }

private:
    uint8_t* buffer_;
    size_t capacity_;
    size_t size_;
    uintptr_t address_;
};

InstructionKind DecodeKind(uint32_t instruction) noexcept;
bool IsBti(uint32_t instruction) noexcept;
bool IsPacEntry(uint32_t instruction, uint32_t* authenticate) noexcept;
bool IsRegisterBranchWithLink(uint32_t instruction) noexcept;
bool IsExceptionGeneration(uint32_t instruction) noexcept;

uintptr_t DecodePcRelativeTarget(uint32_t instruction,
                                 uintptr_t pc) noexcept;
bool EncodePcRelative(uint32_t instruction, uintptr_t pc,
                      uintptr_t target, uint32_t* encoded) noexcept;
bool EncodeBranch(uintptr_t pc, uintptr_t target, bool link,
                  uint32_t* encoded) noexcept;
bool EncodeLdrLiteralX(uint32_t reg, uintptr_t pc, uintptr_t literal,
                       uint32_t* encoded) noexcept;
bool EncodeLiteralMemoryLoad(uint32_t original, uint32_t base_reg,
                             uint32_t* encoded) noexcept;
uint32_t InvertConditional(uint32_t instruction) noexcept;
bool IsUnconditionalBranch(uint32_t instruction) noexcept;

}  // namespace hookself::inline_hook::arm64

#endif
