#include <stdint.h>

extern uint64_t hs_elf_fixture_gnu_target(uint64_t value);
extern uint64_t hs_elf_fixture_sysv_target(uint64_t value);
extern uint64_t hs_elf_fixture_gnu_data;

__attribute__((visibility("default"), noinline))
uint64_t hs_elf_consumer_call_gnu(uint64_t value) {
    return hs_elf_fixture_gnu_target(value);
}

__attribute__((visibility("default"), noinline))
uint64_t hs_elf_consumer_call_sysv(uint64_t value) {
    return hs_elf_fixture_sysv_target(value);
}

__attribute__((visibility("default"), noinline))
uintptr_t hs_elf_consumer_gnu_address(void) {
    return (uintptr_t)&hs_elf_fixture_gnu_target;
}

__attribute__((visibility("default"), noinline))
uintptr_t hs_elf_consumer_sysv_address(void) {
    return (uintptr_t)&hs_elf_fixture_sysv_target;
}

__attribute__((visibility("default"), noinline))
uintptr_t hs_elf_consumer_gnu_data_address(void) {
    return (uintptr_t)&hs_elf_fixture_gnu_data;
}
