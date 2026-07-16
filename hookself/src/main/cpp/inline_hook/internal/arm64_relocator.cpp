#include "inline_hook/internal/arm64_relocator.h"

#include "inline_hook/internal/arm64_encoding.h"

namespace hookself::inline_hook::arm64 {
namespace {

struct LiteralFixup {
    size_t instruction_offset;
    uint32_t reg;
    uint64_t value;
};

uintptr_t MapInternalTarget(const RelocationRequest& request,
                            uintptr_t target) noexcept {
    for (size_t index = 0; index < request.internal_map_count; ++index) {
        if (request.internal_maps[index].source == target) {
            return request.internal_maps[index].destination;
        }
    }
    return target;
}

bool EmitLoadAddress(CodeWriter* writer, uint32_t reg, uint64_t value,
                     LiteralFixup* fixups, size_t* fixup_count,
                     size_t fixup_capacity) noexcept {
    if (writer == nullptr || fixups == nullptr || fixup_count == nullptr ||
        *fixup_count >= fixup_capacity) {
        return false;
    }
    LiteralFixup& fixup = fixups[(*fixup_count)++];
    fixup.instruction_offset = writer->size();
    fixup.reg = reg;
    fixup.value = value;
    return writer->Emit32(0U);
}

bool FinalizeLiterals(CodeWriter* writer, LiteralFixup* fixups,
                      size_t fixup_count) noexcept {
    if (writer == nullptr || (fixup_count != 0U && fixups == nullptr)) {
        return false;
    }
    for (size_t index = 0; index < fixup_count; ++index) {
        if (!writer->Align8()) {
            return false;
        }
        const uintptr_t literal_address = writer->address();
        if (!writer->Emit64(fixups[index].value)) {
            return false;
        }
        uint32_t load = 0;
        if (!EncodeLdrLiteralX(
                    fixups[index].reg,
                    writer->address_at(fixups[index].instruction_offset),
                    literal_address, &load) ||
            !writer->Patch32(fixups[index].instruction_offset, load)) {
            return false;
        }
    }
    return true;
}

size_t LiteralAccessSize(uint32_t instruction) noexcept {
    const uint32_t opc = (instruction >> 30U) & 0x3U;
    const uint32_t vector = (instruction >> 26U) & 0x1U;
    if (vector == 0U) {
        if (opc == 0U || opc == 2U) {
            return 4U;
        }
        return opc == 1U ? 8U : 0U;
    }
    if (opc == 0U) {
        return 4U;
    }
    if (opc == 1U) {
        return 8U;
    }
    return opc == 2U ? 16U : 0U;
}

bool OverlapsOverwrittenBytes(const RelocationRequest& request,
                              uint32_t instruction,
                              uintptr_t address) noexcept {
    const size_t access_size = LiteralAccessSize(instruction);
    if (access_size == 0U) {
        return false;
    }
    if (request.overwritten_size == 0U) {
        return false;
    }
    if (request.overwritten_start >
                UINTPTR_MAX - request.overwritten_size ||
        address > UINTPTR_MAX - access_size) {
        return true;
    }
    const uintptr_t access_end = address + access_size;
    const uintptr_t overwritten_end =
            request.overwritten_start + request.overwritten_size;
    return address < overwritten_end &&
           request.overwritten_start < access_end;
}

}  // namespace

RelocationStatus RelocateOneAndContinue(
        const RelocationRequest& request,
        RelocationResult* result) noexcept {
    if (result == nullptr || request.output == nullptr ||
        request.output_capacity < sizeof(uint32_t) ||
        request.source_pc == 0U || request.output_address == 0U ||
        (request.internal_map_count != 0U &&
         request.internal_maps == nullptr)) {
        return RelocationStatus::kInvalidArgument;
    }
    *result = {};
    CodeWriter writer(request.output, request.output_capacity,
                      request.output_address);
    LiteralFixup fixups[2]{};
    size_t fixup_count = 0;
    if (IsRegisterBranchWithLink(request.instruction) ||
        IsExceptionGeneration(request.instruction)) {
        return RelocationStatus::kUnsupported;
    }
    const InstructionKind kind = DecodeKind(request.instruction);
    bool append_continuation = true;

    if (kind == InstructionKind::kB || kind == InstructionKind::kBl) {
        uintptr_t target = DecodePcRelativeTarget(request.instruction,
                                                  request.source_pc);
        target = MapInternalTarget(request, target);
        uint32_t encoded = 0;
        if (kind == InstructionKind::kBl) {
            if (!EmitLoadAddress(&writer, 30U, request.source_pc + 4U,
                                 fixups, &fixup_count, 2U) ||
                !EncodeBranch(writer.address(), target, false, &encoded)) {
                return RelocationStatus::kRange;
            }
            if (!writer.Emit32(encoded)) {
                return RelocationStatus::kNoSpace;
            }
            result->expanded = 1U;
        } else if (EncodePcRelative(request.instruction, writer.address(),
                                    target, &encoded)) {
            if (!writer.Emit32(encoded)) {
                return RelocationStatus::kNoSpace;
            }
        } else {
            return RelocationStatus::kRange;
        }
        append_continuation = false;
    } else if (kind == InstructionKind::kBCond ||
               kind == InstructionKind::kCompareBranch ||
               kind == InstructionKind::kTestBranch) {
        uintptr_t target = DecodePcRelativeTarget(request.instruction,
                                                  request.source_pc);
        target = MapInternalTarget(request, target);
        uint32_t encoded = 0;
        // A64 defines both AL and NV as always true, so neither is invertible.
        const bool always_branch = kind == InstructionKind::kBCond &&
                (request.instruction & 0xeU) == 0xeU;
        if (always_branch) {
            if (!EncodeBranch(writer.address(), target, false, &encoded)) {
                return RelocationStatus::kRange;
            }
            if (!writer.Emit32(encoded)) {
                return RelocationStatus::kNoSpace;
            }
            append_continuation = false;
        } else if (EncodePcRelative(request.instruction, writer.address(),
                                    target, &encoded)) {
            if (!writer.Emit32(encoded)) {
                return RelocationStatus::kNoSpace;
            }
        } else {
            uint32_t skip = 0;
            uint32_t branch = 0;
            const uint32_t inverted = InvertConditional(request.instruction);
            if (!EncodePcRelative(inverted, writer.address(),
                                  writer.address() + 8U, &skip) ||
                !EncodeBranch(writer.address() + 4U, target, false,
                              &branch)) {
                return RelocationStatus::kRange;
            }
            if (!writer.Emit32(skip) || !writer.Emit32(branch)) {
                return RelocationStatus::kNoSpace;
            }
            result->expanded = 1U;
        }
    } else if (kind == InstructionKind::kAdr ||
               kind == InstructionKind::kAdrp) {
        const uintptr_t target = DecodePcRelativeTarget(request.instruction,
                                                        request.source_pc);
        uint32_t encoded = 0;
        if (EncodePcRelative(request.instruction, writer.address(), target,
                             &encoded)) {
            if (!writer.Emit32(encoded)) {
                return RelocationStatus::kNoSpace;
            }
        } else {
            const uint32_t destination = request.instruction & 0x1fU;
            if (destination == 31U) {
                if (!writer.Emit32(kNop)) {
                    return RelocationStatus::kNoSpace;
                }
            } else if (!EmitLoadAddress(&writer, destination, target, fixups,
                                        &fixup_count, 2U)) {
                return RelocationStatus::kNoSpace;
            }
            result->expanded = 1U;
        }
    } else if (kind == InstructionKind::kLiteralLoad) {
        const uintptr_t target = DecodePcRelativeTarget(request.instruction,
                                                        request.source_pc);
        if (OverlapsOverwrittenBytes(request, request.instruction, target)) {
            return RelocationStatus::kUnsupported;
        }
        uint32_t encoded = 0;
        if (EncodePcRelative(request.instruction, writer.address(), target,
                             &encoded)) {
            if (!writer.Emit32(encoded)) {
                return RelocationStatus::kNoSpace;
            }
        } else {
            const uint32_t opc = (request.instruction >> 30U) & 0x3U;
            const uint32_t vector = (request.instruction >> 26U) & 0x1U;
            const uint32_t destination = request.instruction & 0x1fU;
            const bool can_use_destination = vector == 0U && opc != 3U &&
                                             destination != 31U;
            const uint32_t base = can_use_destination ? destination : 17U;
            uint32_t memory_load = 0;
            if (!EncodeLiteralMemoryLoad(request.instruction, base,
                                         &memory_load)) {
                return RelocationStatus::kUnsupported;
            }
            if ((!can_use_destination &&
                 !writer.Emit32(kStrX17PreIndexSpMinus16)) ||
                !EmitLoadAddress(&writer, base, target, fixups,
                                 &fixup_count, 2U) ||
                !writer.Emit32(memory_load) ||
                (!can_use_destination &&
                 !writer.Emit32(kLdrX17PostIndexSpPlus16))) {
                return RelocationStatus::kNoSpace;
            }
            result->expanded = 1U;
            result->uses_x17 = can_use_destination ? 0U : 1U;
        }
    } else {
        if (!writer.Emit32(request.instruction)) {
            return RelocationStatus::kNoSpace;
        }
    }

    if (append_continuation) {
        uint32_t branch = 0;
        if (!EncodeBranch(writer.address(), request.continuation, false,
                          &branch)) {
            return RelocationStatus::kRange;
        }
        if (!writer.Emit32(branch)) {
            return RelocationStatus::kNoSpace;
        }
    }
    result->code_size = writer.size();
    if (!FinalizeLiterals(&writer, fixups, fixup_count)) {
        return RelocationStatus::kNoSpace;
    }
    result->total_size = writer.size();
    return RelocationStatus::kOk;
}

}  // namespace hookself::inline_hook::arm64
