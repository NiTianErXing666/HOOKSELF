#include "elf_hook/internal/elf_image.h"

#include <string.h>

namespace hookself::elf_hook::internal {
namespace {

constexpr uint64_t kFnvOffset = UINT64_C(14695981039346656037);
constexpr uint64_t kFnvPrime = UINT64_C(1099511628211);
constexpr uint32_t kElfClassBits = 64U;

bool CheckedAdd(uintptr_t left, uint64_t right,
                uintptr_t* result) noexcept {
    if (result == nullptr || right > UINTPTR_MAX ||
        left > UINTPTR_MAX - static_cast<uintptr_t>(right)) {
        return false;
    }
    *result = left + static_cast<uintptr_t>(right);
    return true;
}

bool CheckedMultiply(size_t left, size_t right,
                     size_t* result) noexcept {
    if (result == nullptr || (right != 0U && left > SIZE_MAX / right)) {
        return false;
    }
    *result = left * right;
    return true;
}

bool IsAligned(uintptr_t address, size_t alignment) noexcept {
    return alignment != 0U &&
            (address & (static_cast<uintptr_t>(alignment) - 1U)) == 0U;
}

size_t BoundedLength(const char* value, size_t maximum) noexcept {
    if (value == nullptr) {
        return 0U;
    }
    const void* const end = memchr(value, '\0', maximum + 1U);
    return end == nullptr
            ? maximum + 1U
            : static_cast<size_t>(static_cast<const char*>(end) - value);
}

uint64_t HashBytes(const char* value, size_t length) noexcept {
    uint64_t hash = kFnvOffset;
    for (size_t index = 0; index < length; ++index) {
        hash ^= static_cast<uint8_t>(value[index]);
        hash *= kFnvPrime;
    }
    return hash;
}

const char* BaseName(const char* value, size_t length,
                     size_t* base_length) noexcept {
    const char* base = value;
    for (size_t index = 0; index < length; ++index) {
        if (value[index] == '/') {
            base = value + index + 1U;
        }
    }
    if (base_length != nullptr) {
        *base_length = length - static_cast<size_t>(base - value);
    }
    return base;
}

bool HasSlash(const char* value, size_t length) noexcept {
    return value != nullptr && memchr(value, '/', length) != nullptr;
}

bool MatchesModule(const char* query, size_t query_length, bool exact,
                   bool is_main, const char* path,
                   size_t path_length) noexcept {
    if (query_length == 0U) {
        return is_main;
    }
    if (exact) {
        return query_length == path_length &&
                memcmp(query, path, query_length) == 0;
    }
    size_t base_length = 0U;
    const char* const base = BaseName(path, path_length, &base_length);
    return query_length == base_length &&
            memcmp(query, base, query_length) == 0;
}

bool BuildIdentity(const dl_phdr_info* info, size_t path_length, bool is_main,
                   ModuleIdentity* identity) noexcept {
    if (info == nullptr || identity == nullptr || info->dlpi_phdr == nullptr ||
        info->dlpi_phnum == 0U || info->dlpi_phnum > kMaxProgramHeaders ||
        path_length > kMaxInputName ||
        !IsAligned(reinterpret_cast<uintptr_t>(info->dlpi_phdr),
                   alignof(Elf64_Phdr))) {
        return false;
    }
    const char* const path = info->dlpi_name == nullptr ? "" : info->dlpi_name;
    *identity = {};
    identity->load_bias = static_cast<uintptr_t>(info->dlpi_addr);
    identity->program_headers = reinterpret_cast<uintptr_t>(info->dlpi_phdr);
    identity->program_header_count = info->dlpi_phnum;
    identity->path_length = static_cast<uint32_t>(path_length);
    identity->path_hash = HashBytes(path, path_length);
    if (is_main) {
        identity->flags |= HOOKSELF_ELF_MODULE_F_MAIN_EXECUTABLE;
    }
    bool truncated = false;
    CopyPublicString(identity->path, sizeof(identity->path), path, path_length,
                     &truncated);
    if (truncated) {
        identity->flags |= HOOKSELF_ELF_MODULE_F_PATH_TRUNCATED;
    }
    return true;
}

bool IdentityMatches(const ModuleIdentity& identity,
                     const dl_phdr_info* info) noexcept {
    if (info == nullptr || info->dlpi_phdr == nullptr ||
        static_cast<uintptr_t>(info->dlpi_addr) != identity.load_bias ||
        reinterpret_cast<uintptr_t>(info->dlpi_phdr) !=
                identity.program_headers ||
        info->dlpi_phnum != identity.program_header_count) {
        return false;
    }
    const char* const path = info->dlpi_name == nullptr ? "" : info->dlpi_name;
    const size_t length = BoundedLength(path, kMaxInputName);
    return length == identity.path_length && length <= kMaxInputName &&
            HashBytes(path, length) == identity.path_hash;
}

bool BuildModuleView(const ModuleIdentity& identity,
                     const dl_phdr_info* info,
                     ModuleView* module) noexcept {
    if (info == nullptr || module == nullptr || !IdentityMatches(identity, info)) {
        return false;
    }
    *module = {};
    module->identity = identity;
    module->load_start = UINTPTR_MAX;

    uint64_t dynamic_value = 0U;
    uint64_t dynamic_size = 0U;
    uint64_t relro_value = 0U;
    uint64_t relro_size = 0U;
    bool have_dynamic = false;
    bool have_relro = false;
    for (size_t index = 0; index < info->dlpi_phnum; ++index) {
        const Elf64_Phdr& header = info->dlpi_phdr[index];
        if (header.p_type == PT_LOAD && header.p_memsz != 0U) {
            if (module->segment_count == kMaxLoadSegments) {
                return false;
            }
            uintptr_t start = 0U;
            uintptr_t end = 0U;
            if (!CheckedAdd(identity.load_bias, header.p_vaddr, &start) ||
                !CheckedAdd(start, header.p_memsz, &end) || end <= start) {
                return false;
            }
            module->segments[module->segment_count++] = {
                    start, end, header.p_flags};
            if (start < module->load_start) {
                module->load_start = start;
            }
            if (end > module->load_end) {
                module->load_end = end;
            }
        } else if (header.p_type == PT_DYNAMIC) {
            if (have_dynamic || header.p_memsz < sizeof(Elf64_Dyn)) {
                return false;
            }
            have_dynamic = true;
            dynamic_value = header.p_vaddr;
            dynamic_size = header.p_memsz;
        } else if (header.p_type == PT_GNU_RELRO && header.p_memsz != 0U) {
            if (have_relro) {
                return false;
            }
            have_relro = true;
            relro_value = header.p_vaddr;
            relro_size = header.p_memsz;
        }
    }
    if (module->segment_count == 0U || module->load_start == UINTPTR_MAX ||
        !have_dynamic || dynamic_size > SIZE_MAX ||
        !CheckedAdd(identity.load_bias, dynamic_value,
                    &module->dynamic_address)) {
        return false;
    }
    module->dynamic_size = static_cast<size_t>(dynamic_size);
    if (!module->Contains(module->dynamic_address, module->dynamic_size,
                          PF_R) ||
        !IsAligned(module->dynamic_address, alignof(Elf64_Dyn))) {
        return false;
    }
    if (have_relro) {
        if (!CheckedAdd(identity.load_bias, relro_value,
                        &module->relro_start) ||
            !CheckedAdd(module->relro_start, relro_size,
                        &module->relro_end) ||
            module->relro_end <= module->relro_start ||
            !module->Contains(module->relro_start,
                              static_cast<size_t>(relro_size), PF_R)) {
            return false;
        }
    }
    return true;
}

const LoadSegment* FindContainingSegment(const ModuleView& module,
                                         uintptr_t address) noexcept {
    for (size_t index = 0; index < module.segment_count; ++index) {
        const LoadSegment& segment = module.segments[index];
        if (address >= segment.start && address < segment.end &&
            (segment.flags & PF_R) != 0U) {
            return &segment;
        }
    }
    return nullptr;
}

bool SetUniqueValue(uint64_t value, bool* present,
                    uint64_t* destination) noexcept {
    if (present == nullptr || destination == nullptr) {
        return false;
    }
    if (*present && *destination != value) {
        return false;
    }
    *present = true;
    *destination = value;
    return true;
}

uint32_t GnuHash(const char* value, size_t length) noexcept {
    uint32_t hash = 5381U;
    for (size_t index = 0; index < length; ++index) {
        hash = hash * 33U + static_cast<uint8_t>(value[index]);
    }
    return hash;
}

uint32_t SysvHash(const char* value, size_t length) noexcept {
    uint32_t hash = 0U;
    for (size_t index = 0; index < length; ++index) {
        hash = (hash << 4U) + static_cast<uint8_t>(value[index]);
        const uint32_t high = hash & UINT32_C(0xf0000000);
        if (high != 0U) {
            hash ^= high >> 24U;
            hash &= ~high;
        }
    }
    return hash;
}

bool SymbolNameEquals(const DynamicView& dynamic, uint32_t index,
                      const char* name, size_t name_length) noexcept {
    if (index >= dynamic.symbol_count) {
        return false;
    }
    const Elf64_Sym& symbol = dynamic.symbols[index];
    if (symbol.st_name >= dynamic.string_size) {
        return false;
    }
    const char* const stored = dynamic.strings + symbol.st_name;
    const size_t remaining = dynamic.string_size - symbol.st_name;
    const void* const terminator = memchr(stored, '\0', remaining);
    if (terminator == nullptr) {
        return false;
    }
    const size_t stored_length = static_cast<size_t>(
            static_cast<const char*>(terminator) - stored);
    return stored_length == name_length &&
            memcmp(stored, name, name_length) == 0;
}

int32_t BuildSymbolRecord(const ModuleView& module,
                          const DynamicView& dynamic, uint32_t index,
                          uint32_t lookup_flag,
                          SymbolRecord* record) noexcept {
    if (record == nullptr || index >= dynamic.symbol_count) {
        return HOOKSELF_ELF_E_MALFORMED_ELF;
    }
    const Elf64_Sym& symbol = dynamic.symbols[index];
    if (symbol.st_shndx == SHN_UNDEF) {
        return HOOKSELF_ELF_E_SYMBOL_NOT_FOUND;
    }
    const uint32_t type = ELF64_ST_TYPE(symbol.st_info);
    if (type == STT_TLS || type == STT_GNU_IFUNC ||
        symbol.st_shndx == SHN_COMMON) {
        return HOOKSELF_ELF_E_UNSUPPORTED_SYMBOL;
    }
    uintptr_t address = 0U;
    uint32_t flags = lookup_flag;
    if (symbol.st_shndx == SHN_ABS) {
        if (symbol.st_value > UINTPTR_MAX) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        address = static_cast<uintptr_t>(symbol.st_value);
        flags |= HOOKSELF_ELF_SYMBOL_F_ABSOLUTE;
    } else {
        const size_t checked_size = symbol.st_size == 0U
                ? 1U : static_cast<size_t>(symbol.st_size);
        if (symbol.st_size > SIZE_MAX ||
            !module.ResolveAddress(symbol.st_value, checked_size, 0U,
                                   &address)) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
    }
    const uint32_t binding = ELF64_ST_BIND(symbol.st_info);
    if (binding == STB_WEAK) {
        flags |= HOOKSELF_ELF_SYMBOL_F_WEAK;
    }
    *record = {};
    record->address = address;
    record->size = symbol.st_size;
    record->index = index;
    record->binding = binding;
    record->type = type;
    record->visibility = symbol.st_other & 0x3U;
    record->section_index = symbol.st_shndx;
    record->flags = flags;
    return HOOKSELF_ELF_OK;
}

}  // namespace

bool ValidInputName(const char* value, size_t* length) noexcept {
    if (value == nullptr || length == nullptr) {
        return false;
    }
    const size_t parsed = BoundedLength(value, kMaxInputName);
    if (parsed > kMaxInputName) {
        return false;
    }
    *length = parsed;
    return true;
}

void CopyPublicString(char* destination, size_t capacity, const char* source,
                      size_t source_length, bool* truncated) noexcept {
    if (truncated != nullptr) {
        *truncated = source_length >= capacity;
    }
    if (destination == nullptr || capacity == 0U) {
        return;
    }
    const size_t copied = source != nullptr
            ? (source_length < capacity - 1U ? source_length : capacity - 1U)
            : 0U;
    if (copied != 0U) {
        memcpy(destination, source, copied);
    }
    destination[copied] = '\0';
}

bool ModuleView::Contains(uintptr_t address, size_t size,
                          uint32_t required_flags) const noexcept {
    if (address == 0U || size == 0U || address > UINTPTR_MAX - (size - 1U)) {
        return false;
    }
    for (size_t index = 0; index < segment_count; ++index) {
        const LoadSegment& segment = segments[index];
        if ((segment.flags & required_flags) == required_flags &&
            address >= segment.start && address < segment.end &&
            size <= segment.end - address) {
            return true;
        }
    }
    return false;
}

bool ModuleView::ResolveAddress(uint64_t value, size_t size,
                                uint32_t required_flags,
                                uintptr_t* address) const noexcept {
    if (address == nullptr || size == 0U) {
        return false;
    }
    uintptr_t candidate = 0U;
    if (CheckedAdd(identity.load_bias, value, &candidate) &&
        Contains(candidate, size, required_flags)) {
        *address = candidate;
        return true;
    }
    if (value <= UINTPTR_MAX) {
        candidate = static_cast<uintptr_t>(value);
        if (Contains(candidate, size, required_flags)) {
            *address = candidate;
            return true;
        }
    }
    return false;
}

bool ModuleView::IsRelro(uintptr_t address, size_t size) const noexcept {
    return relro_start != 0U && size != 0U && address >= relro_start &&
            address <= relro_end && size <= relro_end - address;
}

int32_t FindUniqueModule(const char* module_name,
                         ModuleIdentity* identity) noexcept {
    if (identity == nullptr) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    const char* const query = module_name == nullptr ? "" : module_name;
    size_t query_length = 0U;
    if (!ValidInputName(query, &query_length)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    struct Context {
        const char* query;
        size_t query_length;
        bool exact;
        uint32_t matches;
        uint32_t visited;
        int32_t error;
        ModuleIdentity identity;
    } context{query, query_length, HasSlash(query, query_length), 0U, 0U,
              HOOKSELF_ELF_OK, {}};

    const auto callback = [](dl_phdr_info* info, size_t, void* opaque) -> int {
        auto* const current = static_cast<Context*>(opaque);
        const char* const path = info->dlpi_name == nullptr
                ? "" : info->dlpi_name;
        const size_t path_length = BoundedLength(path, kMaxInputName);
        const bool is_main = current->visited++ == 0U;
        if (path_length > kMaxInputName ||
            !MatchesModule(current->query, current->query_length,
                           current->exact, is_main, path, path_length)) {
            return 0;
        }
        ++current->matches;
        if (current->matches == 1U &&
            !BuildIdentity(info, path_length, is_main,
                           &current->identity)) {
            current->error = HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        return 0;
    };
    (void)dl_iterate_phdr(callback, &context);
    if (context.matches == 0U) {
        return HOOKSELF_ELF_E_MODULE_NOT_FOUND;
    }
    if (context.matches > 1U) {
        return HOOKSELF_ELF_E_MODULE_AMBIGUOUS;
    }
    if (context.error != HOOKSELF_ELF_OK) {
        return context.error;
    }
    *identity = context.identity;
    return HOOKSELF_ELF_OK;
}

int32_t VisitModule(const ModuleIdentity& identity, ModuleVisitor visitor,
                    void* context) noexcept {
    if (visitor == nullptr || identity.program_headers == 0U ||
        identity.program_header_count == 0U) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    struct VisitContext {
        const ModuleIdentity* identity;
        ModuleVisitor visitor;
        void* opaque;
        bool found;
        int32_t result;
    } visit{&identity, visitor, context, false, HOOKSELF_ELF_E_MODULE_UNLOADED};

    const auto callback = [](dl_phdr_info* info, size_t, void* opaque) -> int {
        auto* const current = static_cast<VisitContext*>(opaque);
        if (!IdentityMatches(*current->identity, info)) {
            return 0;
        }
        current->found = true;
        ModuleView module{};
        if (!BuildModuleView(*current->identity, info, &module)) {
            current->result = HOOKSELF_ELF_E_MALFORMED_ELF;
        } else {
            current->result = current->visitor(module, current->opaque);
        }
        return 1;
    };
    (void)dl_iterate_phdr(callback, &visit);
    return visit.found ? visit.result : HOOKSELF_ELF_E_MODULE_UNLOADED;
}

int32_t ParseDynamic(const ModuleView& module,
                     DynamicView* dynamic) noexcept {
    if (dynamic == nullptr || module.dynamic_address == 0U ||
        module.dynamic_size < sizeof(Elf64_Dyn)) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    *dynamic = {};
    uint64_t symtab_value = 0U;
    uint64_t strtab_value = 0U;
    uint64_t strsz_value = 0U;
    uint64_t syment_value = 0U;
    uint64_t sysv_value = 0U;
    uint64_t gnu_value = 0U;
    uint64_t jmprel_value = 0U;
    uint64_t pltrelsz_value = 0U;
    uint64_t pltrel_value = 0U;
    uint64_t relaent_value = 0U;
    bool have_symtab = false;
    bool have_strtab = false;
    bool have_strsz = false;
    bool have_syment = false;
    bool have_sysv = false;
    bool have_gnu = false;
    bool have_jmprel = false;
    bool have_pltrelsz = false;
    bool have_pltrel = false;
    bool have_relaent = false;
    bool terminated = false;

    const auto* const entries = reinterpret_cast<const Elf64_Dyn*>(
            module.dynamic_address);
    const size_t count = module.dynamic_size / sizeof(Elf64_Dyn);
    for (size_t index = 0; index < count; ++index) {
        const Elf64_Dyn& entry = entries[index];
        if (entry.d_tag == DT_NULL) {
            terminated = true;
            break;
        }
        bool valid = true;
        switch (entry.d_tag) {
            case DT_SYMTAB:
                valid = SetUniqueValue(entry.d_un.d_ptr, &have_symtab,
                                       &symtab_value);
                break;
            case DT_STRTAB:
                valid = SetUniqueValue(entry.d_un.d_ptr, &have_strtab,
                                       &strtab_value);
                break;
            case DT_STRSZ:
                valid = SetUniqueValue(entry.d_un.d_val, &have_strsz,
                                       &strsz_value);
                break;
            case DT_SYMENT:
                valid = SetUniqueValue(entry.d_un.d_val, &have_syment,
                                       &syment_value);
                break;
            case DT_HASH:
                valid = SetUniqueValue(entry.d_un.d_ptr, &have_sysv,
                                       &sysv_value);
                break;
            case DT_GNU_HASH:
                valid = SetUniqueValue(entry.d_un.d_ptr, &have_gnu,
                                       &gnu_value);
                break;
            case DT_JMPREL:
                valid = SetUniqueValue(entry.d_un.d_ptr, &have_jmprel,
                                       &jmprel_value);
                break;
            case DT_PLTRELSZ:
                valid = SetUniqueValue(entry.d_un.d_val, &have_pltrelsz,
                                       &pltrelsz_value);
                break;
            case DT_PLTREL:
                valid = SetUniqueValue(entry.d_un.d_val, &have_pltrel,
                                       &pltrel_value);
                break;
            case DT_RELAENT:
                valid = SetUniqueValue(entry.d_un.d_val, &have_relaent,
                                       &relaent_value);
                break;
            default:
                break;
        }
        if (!valid) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
    }
    if (!terminated || !have_symtab || !have_strtab || !have_strsz ||
        strsz_value == 0U || strsz_value > SIZE_MAX ||
        (have_syment && syment_value != sizeof(Elf64_Sym))) {
        return HOOKSELF_ELF_E_MALFORMED_ELF;
    }

    uintptr_t symbol_address = 0U;
    uintptr_t string_address = 0U;
    if (!module.ResolveAddress(symtab_value, sizeof(Elf64_Sym), PF_R,
                               &symbol_address) ||
        !module.ResolveAddress(strtab_value, static_cast<size_t>(strsz_value),
                               PF_R, &string_address)) {
        return HOOKSELF_ELF_E_MALFORMED_ELF;
    }
    if (!IsAligned(symbol_address, alignof(Elf64_Sym))) {
        return HOOKSELF_ELF_E_MALFORMED_ELF;
    }
    dynamic->symbols = reinterpret_cast<const Elf64_Sym*>(symbol_address);
    dynamic->strings = reinterpret_cast<const char*>(string_address);
    dynamic->string_size = static_cast<size_t>(strsz_value);
    dynamic->module_flags = module.identity.flags;
    if (module.relro_start != 0U) {
        dynamic->module_flags |= HOOKSELF_ELF_MODULE_F_GNU_RELRO;
    }

    uint32_t sysv_symbol_count = 0U;
    if (have_sysv) {
        uintptr_t address = 0U;
        if (!module.ResolveAddress(sysv_value, sizeof(uint32_t) * 2U, PF_R,
                                   &address) ||
            !IsAligned(address, alignof(uint32_t))) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        const auto* const words = reinterpret_cast<const uint32_t*>(address);
        const uint32_t buckets = words[0];
        const uint32_t chains = words[1];
        size_t total_words = 0U;
        size_t total_bytes = 0U;
        if (buckets == 0U || chains == 0U ||
            !CheckedMultiply(static_cast<size_t>(buckets) + chains + 2U,
                             sizeof(uint32_t), &total_bytes) ||
            !module.Contains(address, total_bytes, PF_R)) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        total_words = total_bytes / sizeof(uint32_t);
        (void)total_words;
        dynamic->sysv_hash.bucket_count = buckets;
        dynamic->sysv_hash.chain_count = chains;
        dynamic->sysv_hash.buckets = words + 2U;
        dynamic->sysv_hash.chains = dynamic->sysv_hash.buckets + buckets;
        sysv_symbol_count = chains;
        dynamic->module_flags |= HOOKSELF_ELF_MODULE_F_SYSV_HASH;
    }

    uint32_t gnu_symbol_count = 0U;
    if (have_gnu) {
        uintptr_t address = 0U;
        if (!module.ResolveAddress(gnu_value, sizeof(uint32_t) * 4U, PF_R,
                                   &address) ||
            !IsAligned(address, alignof(uint32_t))) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        const auto* const header = reinterpret_cast<const uint32_t*>(address);
        const uint32_t bucket_count = header[0];
        const uint32_t symbol_offset = header[1];
        const uint32_t bloom_count = header[2];
        const uint32_t bloom_shift = header[3];
        size_t bloom_bytes = 0U;
        size_t bucket_bytes = 0U;
        if (bucket_count == 0U || bloom_count == 0U || bloom_shift >= 32U ||
            !CheckedMultiply(bloom_count, sizeof(Elf64_Addr), &bloom_bytes) ||
            !CheckedMultiply(bucket_count, sizeof(uint32_t), &bucket_bytes) ||
            address > UINTPTR_MAX - sizeof(uint32_t) * 4U ||
            address + sizeof(uint32_t) * 4U > UINTPTR_MAX - bloom_bytes ||
            address + sizeof(uint32_t) * 4U + bloom_bytes >
                    UINTPTR_MAX - bucket_bytes) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        const uintptr_t bloom_address = address + sizeof(uint32_t) * 4U;
        const uintptr_t bucket_address = bloom_address + bloom_bytes;
        const uintptr_t chain_address = bucket_address + bucket_bytes;
        if (!IsAligned(bloom_address, alignof(Elf64_Addr)) ||
            !IsAligned(bucket_address, alignof(uint32_t)) ||
            !IsAligned(chain_address, alignof(uint32_t)) ||
            !module.Contains(bloom_address, bloom_bytes, PF_R) ||
            !module.Contains(bucket_address, bucket_bytes, PF_R)) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        const LoadSegment* const chain_segment =
                FindContainingSegment(module, chain_address);
        if (chain_segment == nullptr) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        const size_t available_chain_words = static_cast<size_t>(
                (chain_segment->end - chain_address) / sizeof(uint32_t));
        const auto* const buckets = reinterpret_cast<const uint32_t*>(
                bucket_address);
        uint32_t maximum_bucket = 0U;
        for (uint32_t index = 0; index < bucket_count; ++index) {
            const uint32_t bucket = buckets[index];
            if (bucket != 0U && bucket < symbol_offset) {
                return HOOKSELF_ELF_E_MALFORMED_ELF;
            }
            if (bucket > maximum_bucket) {
                maximum_bucket = bucket;
            }
        }
        if (maximum_bucket == 0U) {
            gnu_symbol_count = symbol_offset;
        } else {
            size_t chain_index = maximum_bucket - symbol_offset;
            if (chain_index >= available_chain_words) {
                return HOOKSELF_ELF_E_MALFORMED_ELF;
            }
            while ((reinterpret_cast<const uint32_t*>(chain_address)
                            [chain_index] & 1U) == 0U) {
                if (++chain_index >= available_chain_words) {
                    return HOOKSELF_ELF_E_MALFORMED_ELF;
                }
            }
            const uint64_t count64 = static_cast<uint64_t>(symbol_offset) +
                    chain_index + 1U;
            if (count64 > UINT32_MAX) {
                return HOOKSELF_ELF_E_MALFORMED_ELF;
            }
            gnu_symbol_count = static_cast<uint32_t>(count64);
        }
        dynamic->gnu_hash.bucket_count = bucket_count;
        dynamic->gnu_hash.symbol_offset = symbol_offset;
        dynamic->gnu_hash.bloom_count = bloom_count;
        dynamic->gnu_hash.bloom_shift = bloom_shift;
        dynamic->gnu_hash.symbol_count = gnu_symbol_count;
        dynamic->gnu_hash.bloom = reinterpret_cast<const Elf64_Addr*>(
                bloom_address);
        dynamic->gnu_hash.buckets = buckets;
        dynamic->gnu_hash.chains = reinterpret_cast<const uint32_t*>(
                chain_address);
        dynamic->module_flags |= HOOKSELF_ELF_MODULE_F_GNU_HASH;
    }
    if (!have_sysv && !have_gnu) {
        return HOOKSELF_ELF_E_UNSUPPORTED_ELF;
    }
    if (have_sysv && have_gnu && gnu_symbol_count > sysv_symbol_count) {
        return HOOKSELF_ELF_E_MALFORMED_ELF;
    }
    dynamic->symbol_count = have_sysv
            ? sysv_symbol_count : gnu_symbol_count;
    size_t symbol_bytes = 0U;
    if (dynamic->symbol_count == 0U ||
        !CheckedMultiply(dynamic->symbol_count, sizeof(Elf64_Sym),
                         &symbol_bytes) ||
        !module.Contains(symbol_address, symbol_bytes, PF_R)) {
        return HOOKSELF_ELF_E_MALFORMED_ELF;
    }
    if (have_gnu && dynamic->gnu_hash.symbol_count >
                            dynamic->gnu_hash.symbol_offset) {
        size_t chain_bytes = 0U;
        if (!CheckedMultiply(dynamic->gnu_hash.symbol_count -
                                    dynamic->gnu_hash.symbol_offset,
                             sizeof(uint32_t), &chain_bytes) ||
            !module.Contains(reinterpret_cast<uintptr_t>(
                                     dynamic->gnu_hash.chains),
                             chain_bytes, PF_R)) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
    }

    const bool any_plt = have_jmprel || have_pltrelsz || have_pltrel;
    if (any_plt) {
        if (!have_jmprel || !have_pltrelsz || !have_pltrel ||
            pltrel_value != DT_RELA ||
            (have_relaent && relaent_value != sizeof(Elf64_Rela)) ||
            pltrelsz_value == 0U || pltrelsz_value > SIZE_MAX ||
            (pltrelsz_value % sizeof(Elf64_Rela)) != 0U) {
            return HOOKSELF_ELF_E_UNSUPPORTED_ELF;
        }
        uintptr_t relocation_address = 0U;
        if (!module.ResolveAddress(jmprel_value,
                                   static_cast<size_t>(pltrelsz_value), PF_R,
                                   &relocation_address) ||
            !IsAligned(relocation_address, alignof(Elf64_Rela))) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        dynamic->plt_relocations =
                reinterpret_cast<const Elf64_Rela*>(relocation_address);
        dynamic->plt_relocation_count = static_cast<size_t>(
                pltrelsz_value / sizeof(Elf64_Rela));
    }
    return HOOKSELF_ELF_OK;
}

int32_t ResolveSymbol(const ModuleView& module, const DynamicView& dynamic,
                      const char* symbol_name,
                      SymbolRecord* symbol) noexcept {
    size_t name_length = 0U;
    if (symbol == nullptr || !ValidInputName(symbol_name, &name_length) ||
        name_length == 0U) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    if (dynamic.gnu_hash.bucket_count != 0U) {
        const uint32_t hash = GnuHash(symbol_name, name_length);
        const uint32_t word_index =
                (hash / kElfClassBits) % dynamic.gnu_hash.bloom_count;
        const Elf64_Addr word = dynamic.gnu_hash.bloom[word_index];
        const Elf64_Addr mask =
                (Elf64_Addr{1U} << (hash % kElfClassBits)) |
                (Elf64_Addr{1U} << ((hash >> dynamic.gnu_hash.bloom_shift) %
                                    kElfClassBits));
        if ((word & mask) == mask) {
            uint32_t index = dynamic.gnu_hash.buckets[
                    hash % dynamic.gnu_hash.bucket_count];
            if (index >= dynamic.gnu_hash.symbol_offset) {
                while (index < dynamic.gnu_hash.symbol_count) {
                    const uint32_t chain = dynamic.gnu_hash.chains[
                            index - dynamic.gnu_hash.symbol_offset];
                    if ((chain | 1U) == (hash | 1U) &&
                        SymbolNameEquals(dynamic, index, symbol_name,
                                         name_length) &&
                        dynamic.symbols[index].st_shndx != SHN_UNDEF) {
                        return BuildSymbolRecord(
                                module, dynamic, index,
                                HOOKSELF_ELF_SYMBOL_F_GNU_HASH, symbol);
                    }
                    if ((chain & 1U) != 0U) {
                        break;
                    }
                    ++index;
                }
            }
        }
    }
    if (dynamic.sysv_hash.bucket_count != 0U) {
        const uint32_t hash = SysvHash(symbol_name, name_length);
        uint32_t index = dynamic.sysv_hash.buckets[
                hash % dynamic.sysv_hash.bucket_count];
        for (uint32_t steps = 0U;
             index != STN_UNDEF && steps < dynamic.sysv_hash.chain_count;
             ++steps) {
            if (index >= dynamic.sysv_hash.chain_count) {
                return HOOKSELF_ELF_E_MALFORMED_ELF;
            }
            if (SymbolNameEquals(dynamic, index, symbol_name, name_length) &&
                dynamic.symbols[index].st_shndx != SHN_UNDEF) {
                return BuildSymbolRecord(
                        module, dynamic, index,
                        HOOKSELF_ELF_SYMBOL_F_SYSV_HASH, symbol);
            }
            index = dynamic.sysv_hash.chains[index];
        }
    }
    return HOOKSELF_ELF_E_SYMBOL_NOT_FOUND;
}

int32_t CollectJumpSlots(const ModuleView& module,
                         const DynamicView& dynamic,
                         const char* symbol_name,
                         PreparedJumpSlotHook* prepared) noexcept {
    size_t name_length = 0U;
    if (prepared == nullptr || !ValidInputName(symbol_name, &name_length) ||
        name_length == 0U) {
        return HOOKSELF_ELF_E_INVALID_ARGUMENT;
    }
    *prepared = {};
    bool all_relro = true;
    for (size_t index = 0; index < dynamic.plt_relocation_count; ++index) {
        const Elf64_Rela& relocation = dynamic.plt_relocations[index];
        if (ELF64_R_TYPE(relocation.r_info) != R_AARCH64_JUMP_SLOT) {
            continue;
        }
        const uint32_t symbol_index = static_cast<uint32_t>(
                ELF64_R_SYM(relocation.r_info));
        if (symbol_index >= dynamic.symbol_count) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        const uint32_t type = ELF64_ST_TYPE(
                dynamic.symbols[symbol_index].st_info);
        if ((type != STT_FUNC && type != STT_NOTYPE &&
             type != STT_GNU_IFUNC) ||
            !SymbolNameEquals(dynamic, symbol_index, symbol_name,
                              name_length)) {
            continue;
        }
        uintptr_t slot = 0U;
        if (!module.ResolveAddress(relocation.r_offset, sizeof(uintptr_t),
                                   PF_R | PF_W, &slot) ||
            (slot & (alignof(uintptr_t) - 1U)) != 0U) {
            return HOOKSELF_ELF_E_MALFORMED_ELF;
        }
        bool duplicate = false;
        for (uint32_t existing = 0U; existing < prepared->slot_count;
             ++existing) {
            if (prepared->slots[existing] == slot) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        if (prepared->slot_count == kMaxSlotsPerHook) {
            return HOOKSELF_ELF_E_TOO_MANY_SLOTS;
        }
        prepared->slots[prepared->slot_count++] = slot;
        all_relro = all_relro && module.IsRelro(slot, sizeof(uintptr_t));
    }
    if (prepared->slot_count == 0U) {
        return HOOKSELF_ELF_E_RELOCATION_NOT_FOUND;
    }
    prepared->flags = HOOKSELF_ELF_INFO_F_JUMP_SLOT;
    if (all_relro) {
        prepared->flags |= HOOKSELF_ELF_INFO_F_GNU_RELRO;
    }
    if ((module.identity.flags & HOOKSELF_ELF_MODULE_F_PATH_TRUNCATED) != 0U) {
        prepared->flags |= HOOKSELF_ELF_INFO_F_PATH_TRUNCATED;
    }
    return HOOKSELF_ELF_OK;
}

}  // namespace hookself::elf_hook::internal
