#include "task_table.h"

#include <stddef.h>

namespace hookself::tracer {
namespace {

void ZeroBytes(void* memory, size_t size) noexcept {
    auto* bytes = static_cast<uint8_t*>(memory);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = 0;
    }
}

void ClearRecord(TaskRecord* record, uint32_t slot) noexcept {
    ZeroBytes(record, sizeof(*record));
    record->slot = slot;
    record->active_syscall.syscall_number = -1;
    record->active_syscall.user_syscall_number = -1;
    record->active_syscall.executed_syscall_number = -1;
    record->active_syscall.scratch_slot = kInvalidTaskSlot;
    record->active_syscall.nested_ptrace_operation_slot = UINT32_MAX;
}

bool IsValidResumeMode(TaskResumeMode mode) noexcept {
    return mode == TaskResumeMode::kUnknown || mode == TaskResumeMode::kCont ||
           mode == TaskResumeMode::kSyscall;
}

}  // namespace

void Init(TaskTable* table) noexcept {
    if (table == nullptr) {
        return;
    }
    ZeroBytes(table, sizeof(*table));
    table->magic = kTaskTableMagic;
    table->version = kTaskTableVersion;
    for (uint32_t slot = 0; slot < kTaskTableCapacity; ++slot) {
        ClearRecord(&table->tasks[slot], slot);
    }
}

bool IsInitialized(const TaskTable* table) noexcept {
    return table != nullptr && table->magic == kTaskTableMagic &&
           table->version == kTaskTableVersion &&
           table->count <= kTaskTableCapacity &&
           table->free_hint < kTaskTableCapacity;
}

bool Validate(const TaskTable* table) noexcept {
    if (!IsInitialized(table)) {
        return false;
    }

    uint32_t occupied_count = 0;
    for (uint32_t slot = 0; slot < kTaskTableCapacity; ++slot) {
        const TaskRecord& task = table->tasks[slot];
        if (task.slot != slot || task.occupied > 1U) {
            return false;
        }
        if (task.occupied == 0U) {
            if (task.tid != 0 || task.tgid != 0 ||
                task.life != TaskLifeState::kEmpty ||
                task.resume_mode != TaskResumeMode::kUnknown) {
                return false;
            }
            continue;
        }
        if (task.tid <= 0 || task.tgid <= 0 ||
            task.life == TaskLifeState::kEmpty ||
            !IsValidResumeMode(task.resume_mode)) {
            return false;
        }
        ++occupied_count;
        for (uint32_t other = slot + 1; other < kTaskTableCapacity; ++other) {
            if (table->tasks[other].occupied != 0U &&
                table->tasks[other].tid == task.tid) {
                return false;
            }
        }
    }
    return occupied_count == table->count;
}

const TaskRecord* Find(const TaskTable* table, int32_t tid) noexcept {
    if (!IsInitialized(table) || tid <= 0 || table->count == 0U) {
        return nullptr;
    }
    for (uint32_t slot = 0; slot < kTaskTableCapacity; ++slot) {
        const TaskRecord& task = table->tasks[slot];
        if (task.occupied != 0U && task.tid == tid) {
            return &task;
        }
    }
    return nullptr;
}

TaskRecord* Find(TaskTable* table, int32_t tid) noexcept {
    return const_cast<TaskRecord*>(Find(static_cast<const TaskTable*>(table), tid));
}

uint32_t FindSlot(const TaskTable* table, int32_t tid) noexcept {
    const TaskRecord* task = Find(table, tid);
    return task == nullptr ? kInvalidTaskSlot : task->slot;
}

const TaskRecord* At(const TaskTable* table, uint32_t slot) noexcept {
    if (!IsInitialized(table) || slot >= kTaskTableCapacity ||
        table->tasks[slot].occupied == 0U) {
        return nullptr;
    }
    return &table->tasks[slot];
}

TaskRecord* At(TaskTable* table, uint32_t slot) noexcept {
    return const_cast<TaskRecord*>(At(static_cast<const TaskTable*>(table), slot));
}

TaskInsertResult Insert(TaskTable* table, int32_t tid, int32_t tgid,
                        TaskRecord** record) noexcept {
    if (record != nullptr) {
        *record = nullptr;
    }
    if (!IsInitialized(table) || tid <= 0 || tgid <= 0) {
        return TaskInsertResult::kInvalidArgument;
    }

    TaskRecord* existing = Find(table, tid);
    if (existing != nullptr) {
        if (record != nullptr) {
            *record = existing;
        }
        return existing->tgid == tgid ? TaskInsertResult::kAlreadyPresent
                                      : TaskInsertResult::kIdentityConflict;
    }
    if (table->count >= kTaskTableCapacity) {
        return TaskInsertResult::kFull;
    }

    const uint32_t start = table->free_hint;
    for (uint32_t offset = 0; offset < kTaskTableCapacity; ++offset) {
        uint32_t slot = start + offset;
        if (slot >= kTaskTableCapacity) {
            slot -= kTaskTableCapacity;
        }
        TaskRecord* task = &table->tasks[slot];
        if (task->occupied != 0U) {
            continue;
        }

        ClearRecord(task, slot);
        task->occupied = 1U;
        task->tid = tid;
        task->tgid = tgid;
        task->life = TaskLifeState::kDiscovered;
        ++table->count;
        ++table->mutation_generation;
        table->free_hint = slot + 1U;
        if (table->free_hint == kTaskTableCapacity) {
            table->free_hint = 0U;
        }
        if (record != nullptr) {
            *record = task;
        }
        return TaskInsertResult::kInserted;
    }

    return TaskInsertResult::kFull;
}

bool EraseAt(TaskTable* table, uint32_t slot) noexcept {
    TaskRecord* task = At(table, slot);
    if (task == nullptr) {
        return false;
    }

    ClearRecord(task, slot);
    --table->count;
    ++table->mutation_generation;
    table->free_hint = slot;
    return true;
}

bool Erase(TaskTable* table, int32_t tid) noexcept {
    const uint32_t slot = FindSlot(table, tid);
    return slot != kInvalidTaskSlot && EraseAt(table, slot);
}

uint32_t Count(const TaskTable* table) noexcept {
    return IsInitialized(table) ? table->count : 0U;
}

bool Empty(const TaskTable* table) noexcept {
    return Count(table) == 0U;
}

bool Full(const TaskTable* table) noexcept {
    return IsInitialized(table) && table->count == kTaskTableCapacity;
}

void ClearActiveSyscall(TaskRecord* record) noexcept {
    if (record == nullptr) {
        return;
    }
    ZeroBytes(&record->active_syscall, sizeof(record->active_syscall));
    record->active_syscall.syscall_number = -1;
    record->active_syscall.user_syscall_number = -1;
    record->active_syscall.executed_syscall_number = -1;
    record->active_syscall.scratch_slot = kInvalidTaskSlot;
    record->active_syscall.nested_ptrace_operation_slot = UINT32_MAX;
}

}  // namespace hookself::tracer
