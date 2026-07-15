#pragma once

#include <cstddef>
#include <cstdint>

namespace hookself::internal {

enum class ProcVirtualNodeKind : uint32_t {
    kNone = 0,
    kRootDirectory = 1,
    kStatus = 2,
    kMaps = 3,
    kSmaps = 4,
    kSmapsRollup = 5,
    kAttrCurrent = 6,
    kFdDirectory = 7,
    kFdInfoDirectory = 8,
    kMapFilesDirectory = 9,
};

enum ProcVirtualPathFlags : uint32_t {
    kProcVirtualPathNone = 0,
    kProcVirtualPathSelfAlias = 1U << 0,
    kProcVirtualPathThreadSelfAlias = 1U << 1,
    kProcVirtualPathNumericSelector = 1U << 2,
    kProcVirtualPathExplicitTask = 1U << 3,
};

struct ProcVirtualPath {
    ProcVirtualNodeKind kind;
    int32_t subject_pid;
    int32_t subject_tid;
    uint32_t flags;
};

// Parses canonical proc paths. subject_pid is the top-level selector; a
// top-level numeric selector may name either a PID or a TID and must be
// resolved by the caller. subject_tid is nonzero for thread-self and
// explicit task/<tid> forms.
int ParseProcVirtualPath(const char* path, size_t path_length,
                         int32_t caller_tgid, int32_t caller_tid,
                         ProcVirtualPath* output) noexcept;

struct ProcVirtualAddressRange {
    uintptr_t start;
    size_t size;
};

enum ProcReversePathRuleFlags : uint32_t {
    kProcReversePathRuleNone = 0,
    kProcReversePathRuleVisible = 1U << 0,
};

struct ProcReversePathRule {
    const char* host_prefix;
    size_t host_prefix_length;
    const char* guest_prefix;
    size_t guest_prefix_length;
    int32_t priority;
    uint32_t flags;
};

struct ProcTextRewriteOptions {
    const ProcVirtualAddressRange* hidden_ranges;
    size_t hidden_range_count;
    const ProcReversePathRule* reverse_rules;
    size_t reverse_rule_count;
};

struct ProcTextRewriteResult {
    size_t output_size;
    size_t mappings_seen;
    size_t mappings_hidden;
    size_t paths_rewritten;
};

// input and output must not overlap. Both functions validate and size the
// complete snapshot before writing output. They return positive errno values.
int RewriteProcMaps(const uint8_t* input, size_t input_size,
                    uint8_t* output, size_t output_capacity,
                    const ProcTextRewriteOptions& options,
                    ProcTextRewriteResult* result) noexcept;

int RewriteProcSmaps(const uint8_t* input, size_t input_size,
                     uint8_t* output, size_t output_capacity,
                     const ProcTextRewriteOptions& options,
                     ProcTextRewriteResult* result) noexcept;

struct ProcDirentFilterOptions {
    ProcVirtualNodeKind directory_kind;
    int32_t tracer_pid;
    const int32_t* protected_fds;
    size_t protected_fd_count;
    const ProcVirtualAddressRange* hidden_map_ranges;
    size_t hidden_map_range_count;
};

struct ProcDirentCompactResult {
    size_t visible_size;
    size_t records_seen;
    size_t records_hidden;
    int64_t last_d_off;
    int64_t last_visible_d_off;
    bool all_hidden;
};

// Strictly validates one linux_dirent64 result and compacts visible records in
// place without changing retained d_off cookies.
int CompactProcDirents64(uint8_t* buffer, size_t buffer_size,
                         const ProcDirentFilterOptions& options,
                         ProcDirentCompactResult* result) noexcept;

constexpr size_t kProcVirtualXattrNameMax = 255U;

// Models getxattr output. output_capacity == 0 is a size query. Binary values
// are copied exactly and no partial output is produced on ERANGE.
int ApplyXattrGetOverlay(const uint8_t* value, size_t value_size,
                         uint8_t* output, size_t output_capacity,
                         size_t* result_size) noexcept;

struct XattrListOverlayResult {
    size_t output_size;
    size_t names_seen;
    size_t names_emitted;
    bool injected;
};

// Validates a NUL-separated xattr list, removes duplicate names, and appends
// inject_name only when it is not already present. output may equal input.
int ApplyXattrListOverlay(const uint8_t* input, size_t input_size,
                          const char* inject_name, size_t inject_name_length,
                          uint8_t* output, size_t output_capacity,
                          XattrListOverlayResult* result) noexcept;

}  // namespace hookself::internal
