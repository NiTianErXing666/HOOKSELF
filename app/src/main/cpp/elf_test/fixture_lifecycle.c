typedef void (*HsElfLifecycleCallback)(void);

static HsElfLifecycleCallback g_callback;

__attribute__((visibility("default")))
void hs_elf_lifecycle_arm(HsElfLifecycleCallback callback) {
    g_callback = callback;
}

__attribute__((destructor))
static void HsElfLifecycleDestructor(void) {
    if (g_callback != 0) {
        g_callback();
    }
}
