#pragma once

#include <cstddef>
#include <cstdint>

#include "hookself/public_api.h"

namespace hookself::internal {

constexpr uint32_t kEventRingMagic = 0x48534552U;  // HSER
constexpr uint32_t kEventRingVersion = 1U;

struct alignas(64) EventRingHeader {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;
    uint32_t event_size;
    alignas(8) uint64_t write_sequence;
    alignas(8) uint64_t read_sequence;
    alignas(8) uint64_t dropped_events;
    uint64_t reserved[3];
};

static_assert(sizeof(EventRingHeader) == 64, "Event ring header must remain cache-line sized");

size_t EventRingBytes(uint32_t capacity);
bool InitializeEventRing(void* memory, size_t memory_size, uint32_t capacity);
bool PushEvent(EventRingHeader* ring, const HookselfEvent& event);
size_t ReadEvents(EventRingHeader* ring, HookselfEvent* events, size_t capacity);
uint64_t EventRingDropped(const EventRingHeader* ring);

}  // namespace hookself::internal
