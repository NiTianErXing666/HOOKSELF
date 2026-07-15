#include "event_ring.h"

namespace hookself::internal {
namespace {

HookselfEvent* EventSlots(EventRingHeader* ring) {
    return reinterpret_cast<HookselfEvent*>(reinterpret_cast<uint8_t*>(ring) +
                                            sizeof(EventRingHeader));
}

void ZeroBytes(void* memory, size_t size) {
    auto* bytes = static_cast<uint8_t*>(memory);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = 0;
    }
}

void CopyEventNoLibc(HookselfEvent* destination, const HookselfEvent& source) {
    destination->struct_size = source.struct_size;
    destination->kind = source.kind;
    destination->sequence = source.sequence;
    destination->monotonic_time_ns = source.monotonic_time_ns;
    destination->tgid = source.tgid;
    destination->tid = source.tid;
    destination->syscall_number = source.syscall_number;
    destination->phase = source.phase;
    destination->action = source.action;
    destination->error = source.error;
    destination->result = source.result;
    for (size_t i = 0; i < 6; ++i) {
        destination->arguments[i] = source.arguments[i];
    }
    destination->rule_id = source.rule_id;
    destination->flags = source.flags;
    for (size_t i = 0; i < HOOKSELF_EVENT_PATH_CAPACITY; ++i) {
        destination->path[i] = source.path[i];
        destination->translated_path[i] = source.translated_path[i];
    }
}

bool HeaderValid(const EventRingHeader* ring) {
    return ring != nullptr && ring->magic == kEventRingMagic &&
           ring->version == kEventRingVersion && ring->capacity > 0 &&
           ring->capacity <= HOOKSELF_MAX_EVENT_CAPACITY &&
           ring->event_size == sizeof(HookselfEvent);
}

}  // namespace

size_t EventRingBytes(uint32_t capacity) {
    if (capacity == 0 || capacity > HOOKSELF_MAX_EVENT_CAPACITY) {
        return 0;
    }
    return sizeof(EventRingHeader) + static_cast<size_t>(capacity) * sizeof(HookselfEvent);
}

bool InitializeEventRing(void* memory, size_t memory_size, uint32_t capacity) {
    const size_t required = EventRingBytes(capacity);
    if (memory == nullptr || required == 0 || memory_size < required) {
        return false;
    }
    ZeroBytes(memory, required);
    auto* ring = static_cast<EventRingHeader*>(memory);
    ring->magic = kEventRingMagic;
    ring->version = kEventRingVersion;
    ring->capacity = capacity;
    ring->event_size = sizeof(HookselfEvent);
    return true;
}

bool PushEvent(EventRingHeader* ring, const HookselfEvent& event) {
    if (!HeaderValid(ring)) {
        return false;
    }
    const uint64_t write = __atomic_load_n(&ring->write_sequence, __ATOMIC_RELAXED);
    const uint64_t read = __atomic_load_n(&ring->read_sequence, __ATOMIC_ACQUIRE);
    if (write - read >= ring->capacity) {
        __atomic_fetch_add(&ring->dropped_events, 1U, __ATOMIC_RELAXED);
        return false;
    }

    HookselfEvent* slot = &EventSlots(ring)[write % ring->capacity];
    CopyEventNoLibc(slot, event);
    slot->struct_size = sizeof(HookselfEvent);
    slot->sequence = write + 1;
    __atomic_store_n(&ring->write_sequence, write + 1, __ATOMIC_RELEASE);
    return true;
}

size_t ReadEvents(EventRingHeader* ring, HookselfEvent* events, size_t capacity) {
    if (!HeaderValid(ring) || events == nullptr || capacity == 0) {
        return 0;
    }
    const uint64_t read = __atomic_load_n(&ring->read_sequence, __ATOMIC_RELAXED);
    const uint64_t write = __atomic_load_n(&ring->write_sequence, __ATOMIC_ACQUIRE);
    const uint64_t available = write - read;
    const size_t count = available < capacity ? static_cast<size_t>(available) : capacity;
    const HookselfEvent* slots = EventSlots(ring);
    for (size_t i = 0; i < count; ++i) {
        events[i] = slots[(read + i) % ring->capacity];
    }
    __atomic_store_n(&ring->read_sequence, read + count, __ATOMIC_RELEASE);
    return count;
}

uint64_t EventRingDropped(const EventRingHeader* ring) {
    if (!HeaderValid(ring)) {
        return 0;
    }
    return __atomic_load_n(&ring->dropped_events, __ATOMIC_ACQUIRE);
}

}  // namespace hookself::internal
