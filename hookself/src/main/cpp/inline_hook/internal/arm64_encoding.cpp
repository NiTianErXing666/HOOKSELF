#include "inline_hook/internal/arm64_encoding.h"

namespace hookself::inline_hook::arm64 {
namespace {

int64_t SignExtend(uint64_t value, uint32_t bits) noexcept {
    const uint64_t sign = UINT64_C(1) << (bits - 1U);
    const uint64_t mask = (UINT64_C(1) << bits) - 1U;
    value &= mask;
    if ((value & sign) == 0U) {
        return static_cast<int64_t>(value);
    }
    return -static_cast<int64_t>((~value & mask) + 1U);
}

bool SignedDifference(uintptr_t target, uintptr_t source,
                      int64_t* difference) noexcept {
    if (difference == nullptr) {
        return false;
    }
    if (target >= source) {
        const uint64_t magnitude = static_cast<uint64_t>(target - source);
        if (magnitude > static_cast<uint64_t>(INT64_MAX)) {
            return false;
        }
        *difference = static_cast<int64_t>(magnitude);
        return true;
    }
    const uint64_t magnitude = static_cast<uint64_t>(source - target);
    const uint64_t minimum_magnitude = UINT64_C(1) << 63U;
    if (magnitude > minimum_magnitude) {
        return false;
    }
    *difference = magnitude == minimum_magnitude
            ? INT64_MIN
            : -static_cast<int64_t>(magnitude);
    return true;
}

bool EncodeSignedImmediate(int64_t byte_offset, uint32_t bits,
                           uint32_t* immediate) noexcept {
    if (immediate == nullptr || byte_offset % INT64_C(4) != 0) {
        return false;
    }
    const int64_t units = byte_offset / 4;
    const int64_t minimum = -(INT64_C(1) << (bits - 1U));
    const int64_t maximum = (INT64_C(1) << (bits - 1U)) - 1;
    if (units < minimum || units > maximum) {
        return false;
    }
    *immediate = static_cast<uint32_t>(units) &
            ((UINT32_C(1) << bits) - 1U);
    return true;
}

}  // namespace

CodeWriter::CodeWriter(uint8_t* buffer, size_t capacity,
                       uintptr_t address) noexcept
    : buffer_(buffer), capacity_(capacity), size_(0), address_(address) {}

bool CodeWriter::Emit32(uint32_t value) noexcept {
    if (buffer_ == nullptr || size_ > capacity_ ||
        capacity_ - size_ < sizeof(value)) {
        return false;
    }
    __builtin_memcpy(buffer_ + size_, &value, sizeof(value));
    size_ += sizeof(value);
    return true;
}

bool CodeWriter::Emit64(uint64_t value) noexcept {
    if (buffer_ == nullptr || size_ > capacity_ ||
        capacity_ - size_ < sizeof(value)) {
        return false;
    }
    __builtin_memcpy(buffer_ + size_, &value, sizeof(value));
    size_ += sizeof(value);
    return true;
}

bool CodeWriter::Align8() noexcept {
    return (address() & 7U) == 0U || Emit32(kNop);
}

bool CodeWriter::Patch32(size_t offset, uint32_t value) noexcept {
    if (buffer_ == nullptr || offset > size_ ||
        size_ - offset < sizeof(value)) {
        return false;
    }
    __builtin_memcpy(buffer_ + offset, &value, sizeof(value));
    return true;
}

InstructionKind DecodeKind(uint32_t instruction) noexcept {
    if ((instruction & 0x7c000000U) == 0x14000000U) {
        return (instruction & 0x80000000U) != 0U
                ? InstructionKind::kBl
                : InstructionKind::kB;
    }
    // FEAT_HBC uses bit 4 for BC.cond but keeps the B.cond imm19 layout.
    if ((instruction & 0xff000000U) == 0x54000000U) {
        return InstructionKind::kBCond;
    }
    if ((instruction & 0x7e000000U) == 0x34000000U) {
        return InstructionKind::kCompareBranch;
    }
    if ((instruction & 0x7e000000U) == 0x36000000U) {
        return InstructionKind::kTestBranch;
    }
    if ((instruction & 0x1f000000U) == 0x10000000U) {
        return (instruction & 0x80000000U) != 0U
                ? InstructionKind::kAdrp
                : InstructionKind::kAdr;
    }
    if ((instruction & 0x3b000000U) == 0x18000000U) {
        return InstructionKind::kLiteralLoad;
    }
    return InstructionKind::kOther;
}

bool IsBti(uint32_t instruction) noexcept {
    return instruction == kBti || instruction == kBtiC ||
           instruction == kBtiJ || instruction == kBtiJc;
}

bool IsPacEntry(uint32_t instruction, uint32_t* authenticate) noexcept {
    if (instruction == kPaciasp) {
        if (authenticate != nullptr) {
            *authenticate = kAutiasp;
        }
        return true;
    }
    if (instruction == kPacibsp) {
        if (authenticate != nullptr) {
            *authenticate = kAutibsp;
        }
        return true;
    }
    return false;
}

bool IsRegisterBranchWithLink(uint32_t instruction) noexcept {
    const uint32_t register_masked = instruction & 0xfffffc1fU;
    if (register_masked == 0xd63f0000U ||  // BLR
        register_masked == 0xd63f081fU ||  // BLRAAZ
        register_masked == 0xd63f0c1fU) {  // BLRABZ
        return true;
    }
    const uint32_t authenticated_masked = instruction & 0xfffffc00U;
    return authenticated_masked == 0xd73f0800U ||  // BLRAA
           authenticated_masked == 0xd73f0c00U;    // BLRAB
}

bool IsExceptionGeneration(uint32_t instruction) noexcept {
    return (instruction & 0xff000000U) == 0xd4000000U;
}

uintptr_t DecodePcRelativeTarget(uint32_t instruction,
                                 uintptr_t pc) noexcept {
    switch (DecodeKind(instruction)) {
        case InstructionKind::kB:
        case InstructionKind::kBl: {
            const int64_t offset = SignExtend(
                    static_cast<uint64_t>(instruction & 0x03ffffffU) << 2U,
                    28U);
            return pc + static_cast<uintptr_t>(offset);
        }
        case InstructionKind::kBCond:
        case InstructionKind::kCompareBranch:
        case InstructionKind::kLiteralLoad: {
            const int64_t offset = SignExtend(
                    static_cast<uint64_t>((instruction >> 5U) & 0x7ffffU)
                            << 2U,
                    21U);
            return pc + static_cast<uintptr_t>(offset);
        }
        case InstructionKind::kTestBranch: {
            const int64_t offset = SignExtend(
                    static_cast<uint64_t>((instruction >> 5U) & 0x3fffU)
                            << 2U,
                    16U);
            return pc + static_cast<uintptr_t>(offset);
        }
        case InstructionKind::kAdr:
        case InstructionKind::kAdrp: {
            const uint64_t immediate =
                    ((static_cast<uint64_t>(instruction) >> 29U) & 0x3U) |
                    (((static_cast<uint64_t>(instruction) >> 5U) & 0x7ffffU)
                     << 2U);
            int64_t offset = SignExtend(immediate, 21U);
            if (DecodeKind(instruction) == InstructionKind::kAdrp) {
                offset *= INT64_C(4096);
                pc &= ~static_cast<uintptr_t>(0xfffU);
            }
            return pc + static_cast<uintptr_t>(offset);
        }
        default:
            return 0;
    }
}

bool EncodePcRelative(uint32_t instruction, uintptr_t pc,
                      uintptr_t target, uint32_t* encoded) noexcept {
    if (encoded == nullptr) {
        return false;
    }
    const InstructionKind kind = DecodeKind(instruction);
    int64_t offset = 0;
    uint32_t immediate = 0;
    switch (kind) {
        case InstructionKind::kB:
        case InstructionKind::kBl:
            if (!SignedDifference(target, pc, &offset)) {
                return false;
            }
            if (!EncodeSignedImmediate(offset, 26U, &immediate)) {
                return false;
            }
            *encoded = (instruction & 0xfc000000U) | immediate;
            return true;
        case InstructionKind::kBCond:
        case InstructionKind::kCompareBranch:
        case InstructionKind::kLiteralLoad:
            if (!SignedDifference(target, pc, &offset)) {
                return false;
            }
            if (!EncodeSignedImmediate(offset, 19U, &immediate)) {
                return false;
            }
            *encoded = (instruction & ~(0x7ffffU << 5U)) |
                    (immediate << 5U);
            return true;
        case InstructionKind::kTestBranch:
            if (!SignedDifference(target, pc, &offset)) {
                return false;
            }
            if (!EncodeSignedImmediate(offset, 14U, &immediate)) {
                return false;
            }
            *encoded = (instruction & ~(0x3fffU << 5U)) |
                    (immediate << 5U);
            return true;
        case InstructionKind::kAdr:
        case InstructionKind::kAdrp: {
            if (kind == InstructionKind::kAdrp) {
                int64_t page_bytes = 0;
                const uintptr_t source_page =
                        pc & ~static_cast<uintptr_t>(0xfffU);
                const uintptr_t target_page =
                        target & ~static_cast<uintptr_t>(0xfffU);
                if (!SignedDifference(target_page, source_page,
                                      &page_bytes)) {
                    return false;
                }
                offset = page_bytes / INT64_C(4096);
            } else if (!SignedDifference(target, pc, &offset)) {
                return false;
            }
            const int64_t minimum = -(INT64_C(1) << 20U);
            const int64_t maximum = (INT64_C(1) << 20U) - 1;
            if (offset < minimum || offset > maximum) {
                return false;
            }
            const uint32_t value = static_cast<uint32_t>(offset) & 0x1fffffU;
            *encoded = (instruction & ~((0x3U << 29U) |
                                        (0x7ffffU << 5U))) |
                    ((value & 0x3U) << 29U) |
                    (((value >> 2U) & 0x7ffffU) << 5U);
            return true;
        }
        default:
            return false;
    }
}

bool EncodeBranch(uintptr_t pc, uintptr_t target, bool link,
                  uint32_t* encoded) noexcept {
    const uint32_t instruction = link ? 0x94000000U : 0x14000000U;
    return EncodePcRelative(instruction, pc, target, encoded);
}

bool EncodeLdrLiteralX(uint32_t reg, uintptr_t pc, uintptr_t literal,
                       uint32_t* encoded) noexcept {
    if (reg > 31U) {
        return false;
    }
    return EncodePcRelative(0x58000000U | reg, pc, literal, encoded);
}

bool EncodeLiteralMemoryLoad(uint32_t original, uint32_t base_reg,
                             uint32_t* encoded) noexcept {
    if (encoded == nullptr || base_reg > 31U ||
        DecodeKind(original) != InstructionKind::kLiteralLoad) {
        return false;
    }
    const uint32_t opc = (original >> 30U) & 0x3U;
    const uint32_t vector = (original >> 26U) & 0x1U;
    const uint32_t rt = original & 0x1fU;
    uint32_t base = 0;
    if (vector == 0U) {
        switch (opc) {
            case 0U: base = 0xb9400000U; break;  // LDR Wt, [Xn]
            case 1U: base = 0xf9400000U; break;  // LDR Xt, [Xn]
            case 2U: base = 0xb9800000U; break;  // LDRSW Xt, [Xn]
            case 3U: base = 0xf9800000U; break;  // PRFM op, [Xn]
            default: return false;
        }
    } else {
        switch (opc) {
            case 0U: base = 0xbd400000U; break;  // LDR St, [Xn]
            case 1U: base = 0xfd400000U; break;  // LDR Dt, [Xn]
            case 2U: base = 0x3dc00000U; break;  // LDR Qt, [Xn]
            default: return false;
        }
    }
    *encoded = base | (base_reg << 5U) | rt;
    return true;
}

uint32_t InvertConditional(uint32_t instruction) noexcept {
    switch (DecodeKind(instruction)) {
        case InstructionKind::kBCond:
            return instruction ^ 0x1U;
        case InstructionKind::kCompareBranch:
        case InstructionKind::kTestBranch:
            return instruction ^ (1U << 24U);
        default:
            return instruction;
    }
}

bool IsUnconditionalBranch(uint32_t instruction) noexcept {
    return DecodeKind(instruction) == InstructionKind::kB;
}

}  // namespace hookself::inline_hook::arm64
