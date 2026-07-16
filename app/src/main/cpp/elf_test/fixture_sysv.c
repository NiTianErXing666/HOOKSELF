#include <stdint.h>

__attribute__((visibility("default"), noinline))
uint64_t hs_elf_fixture_sysv_target(uint64_t value) {
    return value + UINT64_C(17);
}
