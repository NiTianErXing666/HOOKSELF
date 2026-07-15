#include <asm/unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/memfd.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main() {
    constexpr uint32_t kUnshare = 1U << 1;
    constexpr int kLeft = 768;
    constexpr int kProtected = 769;
    constexpr int kRight = 770;
    const int source = static_cast<int>(
            syscall(__NR_memfd_create, "hookself-unshare-kernel-probe",
                    MFD_CLOEXEC));
    const long left_dup = source >= 0
            ? syscall(__NR_dup3, source, kLeft, O_CLOEXEC)
            : -1;
    const long protected_dup = source >= 0
            ? syscall(__NR_dup3, source, kProtected, O_CLOEXEC)
            : -1;
    const long right_dup = source >= 0
            ? syscall(__NR_dup3, source, kRight, O_CLOEXEC)
            : -1;
    const long unshare = syscall(436, UINT32_MAX, UINT32_MAX, kUnshare);
    const long after_unshare = fcntl(kProtected, F_GETFD);
    const long left_close = syscall(436, kLeft, kLeft, 0);
    const long right_close = syscall(436, kRight, kRight, 0);
    const long final_left = fcntl(kLeft, F_GETFD);
    const long final_protected = fcntl(kProtected, F_GETFD);
    const long final_right = fcntl(kRight, F_GETFD);
    printf("source=%d dup=%ld/%ld/%ld unshare=%ld after=%ld "
           "close=%ld/%ld final=%ld/%ld/%ld errno=%d\n",
           source, left_dup, protected_dup, right_dup, unshare, after_unshare,
           left_close, right_close, final_left, final_protected, final_right,
           errno);
    if (source >= 0) {
        (void)syscall(__NR_close, source);
    }
    (void)syscall(__NR_close, kLeft);
    (void)syscall(__NR_close, kProtected);
    (void)syscall(__NR_close, kRight);
    return source >= 0 && left_dup == kLeft && protected_dup == kProtected &&
                           right_dup == kRight && unshare == 0 &&
                           after_unshare >= 0 && left_close == 0 &&
                           right_close == 0 && final_left == -1 &&
                           final_protected >= 0 && final_right == -1
                   ? 0
                   : 1;
}
