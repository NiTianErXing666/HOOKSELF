#include "remote_syscall_arm64.h"

#include <errno.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#include "arch/arm64_regs.h"
#include "platform/raw_syscall_arm64.h"

namespace hookself::tracer {
namespace {

constexpr size_t kWordSize = sizeof(uint64_t);
constexpr uint32_t kSvcZero = 0xd4000001U;
constexpr uint32_t kBrkHookself =
        0xd4200000U | (static_cast<uint32_t>(0x4853U) << 5U);

int ReadTraceeBytes(pid_t tid, uintptr_t address, void* output,
                    size_t size) noexcept {
    if (tid <= 0 || (size != 0 && output == nullptr)) {
        return EINVAL;
    }
    auto* bytes = static_cast<uint8_t*>(output);
    size_t copied = 0;
    while (copied < size) {
        const uintptr_t current = address + copied;
        const uintptr_t aligned = current & ~(kWordSize - 1U);
        const size_t offset = static_cast<size_t>(current - aligned);
        const size_t available = kWordSize - offset;
        const size_t chunk = available < size - copied
                                     ? available
                                     : size - copied;
        uint64_t word = 0;
        const int error = hookself::platform::PtracePeekData(
                tid, aligned, &word);
        if (error != 0) {
            return error;
        }
        const auto* word_bytes = reinterpret_cast<const uint8_t*>(&word);
        for (size_t index = 0; index < chunk; ++index) {
            bytes[copied + index] = word_bytes[offset + index];
        }
        copied += chunk;
    }
    return 0;
}

int WriteTraceeBytes(pid_t tid, uintptr_t address, const void* input,
                     size_t size) noexcept {
    if (tid <= 0 || (size != 0 && input == nullptr)) {
        return EINVAL;
    }
    const auto* bytes = static_cast<const uint8_t*>(input);
    size_t copied = 0;
    while (copied < size) {
        const uintptr_t current = address + copied;
        const uintptr_t aligned = current & ~(kWordSize - 1U);
        const size_t offset = static_cast<size_t>(current - aligned);
        const size_t available = kWordSize - offset;
        const size_t chunk = available < size - copied
                                     ? available
                                     : size - copied;
        uint64_t word = 0;
        if (offset != 0 || chunk != kWordSize) {
            const int peek_error = hookself::platform::PtracePeekData(
                    tid, aligned, &word);
            if (peek_error != 0) {
                return peek_error;
            }
        }
        auto* word_bytes = reinterpret_cast<uint8_t*>(&word);
        for (size_t index = 0; index < chunk; ++index) {
            word_bytes[offset + index] = bytes[copied + index];
        }
        const long poke_result = hookself::platform::RawPtrace(
                PTRACE_POKEDATA, tid, aligned,
                static_cast<uintptr_t>(word));
        const int poke_error = hookself::platform::RawError(poke_result);
        if (poke_error != 0) {
            return poke_error;
        }
        copied += chunk;
    }
    return 0;
}

void EncodeInstruction(uint32_t instruction, uint8_t output[4]) noexcept {
    output[0] = static_cast<uint8_t>(instruction);
    output[1] = static_cast<uint8_t>(instruction >> 8U);
    output[2] = static_cast<uint8_t>(instruction >> 16U);
    output[3] = static_cast<uint8_t>(instruction >> 24U);
}

int WaitForInjectedTrap(pid_t tid, uint32_t* seccomp_stops) noexcept {
    for (;;) {
        int status = 0;
        const long waited = hookself::platform::RawWait4(
                tid, &status, hookself::platform::kWaitWall);
        const int wait_error = hookself::platform::RawError(waited);
        if (wait_error == EINTR) {
            continue;
        }
        if (wait_error != 0 || waited != tid) {
            return wait_error != 0 ? wait_error : ECHILD;
        }
        if (!WIFSTOPPED(status)) {
            return ECHILD;
        }
        const int signal_number = WSTOPSIG(status);
        const uint32_t ptrace_event =
                static_cast<uint32_t>(status) >> 16U;
        if (signal_number == SIGTRAP &&
            ptrace_event == PTRACE_EVENT_SECCOMP) {
            ++*seccomp_stops;
            const long resume = hookself::platform::RawPtrace(
                    PTRACE_CONT, tid, 0, 0);
            const int resume_error = hookself::platform::RawError(resume);
            if (resume_error != 0) {
                return resume_error;
            }
            continue;
        }
        return signal_number == SIGTRAP && ptrace_event == 0U ? 0 : EPROTO;
    }
}

}  // namespace

int InvokeStoppedArm64Syscall(
        pid_t tid, int32_t syscall_number, const uint64_t arguments[6],
        RemoteSyscallArm64Result* result) noexcept {
    if (tid <= 0 || syscall_number < 0 || arguments == nullptr ||
        result == nullptr) {
        return EINVAL;
    }
    *result = {};

    hookself::arch::Arm64Regs saved{};
    int error = hookself::arch::ReadRegisters(tid, &saved);
    if (error != 0 || saved.pc == 0 || (saved.pc & 3U) != 0) {
        return error != 0 ? error : EPROTO;
    }

    uint8_t saved_code[8]{};
    error = ReadTraceeBytes(tid, static_cast<uintptr_t>(saved.pc),
                            saved_code, sizeof(saved_code));
    if (error != 0) {
        return error;
    }
    uint8_t injected_code[8]{};
    EncodeInstruction(kSvcZero, injected_code);
    EncodeInstruction(kBrkHookself, injected_code + 4U);
    error = WriteTraceeBytes(tid, static_cast<uintptr_t>(saved.pc),
                             injected_code, sizeof(injected_code));
    if (error != 0) {
        return error;
    }

    hookself::arch::Arm64Regs injected = saved;
    for (size_t index = 0; index < 6U; ++index) {
        injected.regs[index] = arguments[index];
    }
    injected.regs[8] = static_cast<uint64_t>(
            static_cast<uint32_t>(syscall_number));
    error = hookself::arch::WriteRegisters(tid, &injected);
    if (error == 0) {
        const long resume = hookself::platform::RawPtrace(
                PTRACE_CONT, tid, 0, 0);
        error = hookself::platform::RawError(resume);
    }
    if (error == 0) {
        error = WaitForInjectedTrap(tid, &result->seccomp_stops);
    }

    hookself::arch::Arm64Regs completed{};
    if (error == 0) {
        error = hookself::arch::ReadRegisters(tid, &completed);
        if (error == 0) {
            result->value = static_cast<int64_t>(completed.regs[0]);
        }
    }

    const int code_restore_error = WriteTraceeBytes(
            tid, static_cast<uintptr_t>(saved.pc), saved_code,
            sizeof(saved_code));
    const int register_restore_error =
            hookself::arch::WriteRegisters(tid, &saved);
    if (code_restore_error != 0 || register_restore_error != 0) {
        return EOWNERDEAD;
    }
    return error;
}

}  // namespace hookself::tracer
