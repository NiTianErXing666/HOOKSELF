#include <stdint.h>

__attribute__((visibility("default"), noinline))
uint64_t hs_elf_fixture_gnu_target(uint64_t value) {
    return value + UINT64_C(11);
}

__attribute__((visibility("default")))
uint64_t hs_elf_fixture_gnu_data = UINT64_C(0x47554e5548415348);
