#include "wait_decoder.h"

#include <signal.h>

namespace hookself::tracer {
namespace {

constexpr int32_t kStoppedStatus = 0x7f;
constexpr int32_t kSyscallStopBit = 0x80;

bool IsStopped(int32_t status) {
    return (status & 0xff) == kStoppedStatus;
}

bool IsExited(int32_t status) {
    return (status & 0x7f) == 0;
}

bool IsSignaled(int32_t status) {
    const int32_t signal_number = status & 0x7f;
    return signal_number != 0 && signal_number != kStoppedStatus;
}

int32_t StopSignal(int32_t status) {
    return (status >> 8) & 0xff;
}

uint32_t PtraceEventCode(int32_t status) {
    return static_cast<uint32_t>(status) >> 16;
}

StopEvent EmptyEvent(int32_t status, const WaitDecodeOptions& options) {
    StopEvent event{};
    event.kind = StopEventKind::kUnknown;
    event.event_stop_reason = EventStopReason::kNone;
    event.raw_status = status;
    event.tracesysgood =
            (options.ptrace_options & kPtraceOptionTraceSysgood) != 0 ? 1 : 0;
    return event;
}

}  // namespace

bool IsJobControlStopSignal(int32_t signal_number) {
    return signal_number == SIGSTOP || signal_number == SIGTSTP ||
           signal_number == SIGTTIN || signal_number == SIGTTOU;
}

StopEvent DecodeWaitStatus(int32_t status, const WaitDecodeOptions& options) {
    StopEvent event = EmptyEvent(status, options);

    if (IsExited(status)) {
        event.kind = StopEventKind::kExited;
        event.exit_code = (status >> 8) & 0xff;
        return event;
    }
    if (IsSignaled(status)) {
        event.kind = StopEventKind::kSignaled;
        event.signal = status & 0x7f;
        event.core_dumped = (status & 0x80) != 0 ? 1 : 0;
        return event;
    }
    if (!IsStopped(status)) {
        return event;
    }

    event.signal = StopSignal(status);
    event.ptrace_event = PtraceEventCode(status);

    if (event.ptrace_event == 0 && event.tracesysgood != 0 &&
        event.signal == (SIGTRAP | kSyscallStopBit)) {
        event.kind = StopEventKind::kSyscallStop;
        return event;
    }

    if (event.ptrace_event != 0) {
        if (event.ptrace_event == kPtraceEventSeccomp) {
            event.kind = StopEventKind::kSeccompStop;
        } else if (event.ptrace_event == kPtraceEventStop) {
            if (IsJobControlStopSignal(event.signal)) {
                event.kind = StopEventKind::kGroupStop;
                event.event_stop_reason = EventStopReason::kGroupStop;
            } else if (event.signal == SIGTRAP) {
                event.kind = StopEventKind::kPtraceEvent;
                event.event_stop_reason = EventStopReason::kInterrupt;
            } else {
                event.kind = StopEventKind::kPtraceEvent;
                event.event_stop_reason = EventStopReason::kUnknown;
            }
        } else {
            event.kind = StopEventKind::kPtraceEvent;
        }
        return event;
    }

    if (options.signal_stop_hint == SignalStopHint::kGroupStop &&
        IsJobControlStopSignal(event.signal)) {
        event.kind = StopEventKind::kGroupStop;
        event.event_stop_reason = EventStopReason::kGroupStop;
        return event;
    }

    event.kind = StopEventKind::kSignalDelivery;
    return event;
}

}  // namespace hookself::tracer
