#include <stdint.h>

extern uint64_t hs_elf_fixture_gnu_target(uint64_t value);

__attribute__((visibility("default"), noinline))
uint64_t hs_elf_unloadable_call(uint64_t value) {
    return hs_elf_fixture_gnu_target(value);
}
