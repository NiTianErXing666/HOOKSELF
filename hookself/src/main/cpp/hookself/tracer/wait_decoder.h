#pragma once

#include <cstdint>

namespace hookself::tracer {

constexpr uint64_t kPtraceOptionTraceSysgood = 0x00000001ULL;
constexpr uint32_t kPtraceEventSeccomp = 7U;
constexpr uint32_t kPtraceEventStop = 128U;

enum class StopEventKind : int32_t {
    kUnknown = 0,
    kExited = 1,
    kSignaled = 2,
    kSyscallStop = 3,
    kPtraceEvent = 4,
    kGroupStop = 5,
    kSignalDelivery = 6,
    kSeccompStop = 7,
};

enum class EventStopReason : int32_t {
    kNone = 0,
    kInterrupt = 1,
    kGroupStop = 2,
    kUnknown = 3,
};

// PTRACE_EVENT_STOP is self-describing. This hint is only needed for legacy
// event-less stops after the caller has attempted PTRACE_GETSIGINFO.
enum class SignalStopHint : int32_t {
    kUnknown = 0,
    kSignalDelivery = 1,
    kGroupStop = 2,
};

struct WaitDecodeOptions {
    uint64_t ptrace_options;
    SignalStopHint signal_stop_hint;
    int32_t reserved;
};

struct StopEvent {
    StopEventKind kind;
    EventStopReason event_stop_reason;
    int32_t raw_status;
    int32_t signal;
    int32_t exit_code;
    uint32_t ptrace_event;
    int32_t core_dumped;
    int32_t tracesysgood;
};

bool IsJobControlStopSignal(int32_t signal_number);
StopEvent DecodeWaitStatus(int32_t status, const WaitDecodeOptions& options);

}  // namespace hookself::tracer
