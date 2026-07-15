#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "hookself/internal/fd_identity.h"

namespace {

uint32_t g_checks = 0;
uint32_t g_failures = 0;

void Check(bool condition, const char* expression, int line) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        printf("failure line=%d expression=%s errno=%d\n",
               line, expression, errno);
    }
}

#define CHECK(value) Check((value), #value, __LINE__)

int MakeMemfd(const char* name) {
    return static_cast<int>(syscall(__NR_memfd_create, name, MFD_CLOEXEC));
}

}  // namespace

int main() {
    using hookself::internal::CaptureFdObjectIdentity;
    using hookself::internal::CheckFdObjectIdentity;
    using hookself::internal::CloseFdObject;
    using hookself::internal::FdObjectIdentity;

    int original = MakeMemfd("hookself-fd-identity-original");
    int replacement = MakeMemfd("hookself-fd-identity-replacement");
    CHECK(original >= 0);
    CHECK(replacement >= 0);
    if (original < 0 || replacement < 0) {
        return 1;
    }

    FdObjectIdentity original_identity{};
    CHECK(CaptureFdObjectIdentity(original, &original_identity) == 0);
    CHECK(close(original) == 0);
    CHECK(dup3(replacement, original, O_CLOEXEC) == original);
    CHECK(CheckFdObjectIdentity(original, original_identity) == ESTALE);
    CHECK(CloseFdObject(original, original_identity) == ESTALE);
    CHECK(fcntl(original, F_GETFD) >= 0);

    FdObjectIdentity replacement_identity{};
    CHECK(CaptureFdObjectIdentity(original, &replacement_identity) == 0);
    CHECK(CloseFdObject(original, replacement_identity) == 0);
    CHECK(fcntl(original, F_GETFD) == -1 && errno == EBADF);
    CHECK(fcntl(replacement, F_GETFD) >= 0);
    CHECK(close(replacement) == 0);

    printf("fd_identity_harness: checks=%u failures=%u\n",
           g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
