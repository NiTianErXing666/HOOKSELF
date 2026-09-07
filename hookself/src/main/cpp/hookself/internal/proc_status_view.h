#pragma once

#include <cstddef>
#include <cstdint>

namespace hookself::internal {

struct ProcStatusMetadata {
    int32_t tgid;
    int32_t pid;
    uint64_t tracer_value_offset;
    uint32_t tracer_value_length;
};

// /proc/<pid>/stat 的 State 字段定位：字段 3（最后一个 ')' 之后第一个非空格字符）
struct ProcStatStateMetadata {
    int32_t pid;
    uint64_t state_offset;
};

int ParseProcStatusMetadata(const uint8_t* data, size_t size,
                            int32_t expected_tgid,
                            ProcStatusMetadata* metadata) noexcept;

size_t RewriteTracerPidValue(uint8_t* data, size_t size) noexcept;

bool TracerPidValueIsZero(const uint8_t* data, size_t size,
                          const ProcStatusMetadata& metadata) noexcept;

// status 的 State 行等长虚拟化："t (tracing stop)" → "S (sleeping)" + 尾部空格补齐。
// read 返回值长度不能变（回读校验依赖等长），因此只能原位替换。
size_t RewriteProcStatusStateLine(uint8_t* data, size_t size) noexcept;

int ParseProcStatStateMetadata(const uint8_t* data, size_t size,
                               int32_t expected_pid,
                               ProcStatStateMetadata* metadata) noexcept;

// stat 的 State 字符等长虚拟化：'t'（tracing stop）→ 'S'
size_t RewriteProcStatStateTraced(uint8_t* data, size_t size) noexcept;

// wchan 等长虚拟化：被 ptrace 停止的任务 wchan="ptrace_stop"（11 字节），
// 等长替换为真实内核符号 "wait_waking"；其他含 "ptrace" 的变体用
// 循环 "futex_wait" 填充同长度。无 "ptrace" 时不动。
size_t RewriteProcWchanContent(uint8_t* data, size_t size) noexcept;

}  // namespace hookself::internal
