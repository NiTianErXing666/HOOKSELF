package com.io.hookself;

import android.content.Context;

import java.io.File;

public final class NativeTestBridge {
    static {
        System.loadLibrary("hookself");
        System.loadLibrary("hookself_inline");
        System.loadLibrary("hookself_elf");
        System.loadLibrary("hookself_demo");
    }

    private NativeTestBridge() {
    }

    public static native String detachDemo();
    public static native String runM0Probe();
    public static native String runM1Observation();
    public static native String runM2Redirect(String filesDir);
    public static native String runM2MissingRedirect(String filesDir);
    public static native String runM4CapabilityProbe();
    public static native String runM4CapabilityProbeForceFallback();
    public static native String runM4FaultProbe(int flags);
    public static native String runInlineHookSelfTest();
    public static native String runElfHookSelfTest();

    public static String runFrameworkSelfTest(Context context) {
        return runFrameworkSelfTestNative(virtualBackingDir(context));
    }

    public static String runProcVirtualResidentSmokeTest(Context context) {
        return runProcVirtualResidentSmokeTestNative(virtualBackingDir(context));
    }

    public static native String runNestedPtraceResidentSelfTestNative();

    public static String runResidentSelfTest(Context context) {
        return runResidentSelfTestNative(virtualBackingDir(context));
    }

    public static String runSelectiveRuntimeSelfTest(
            Context context, int iterations) {
        return runSelectiveRuntimeSelfTestNative(
                iterations, virtualBackingDir(context));
    }

    private static String virtualBackingDir(Context context) {
        File root = new File(context.getNoBackupFilesDir(), "hookself");
        if ((!root.exists() && !root.mkdirs()) || !root.isDirectory()) {
            return "";
        }
        return root.getAbsolutePath();
    }

    private static native String runFrameworkSelfTestNative(
            String virtualBackingDir);
    private static native String runProcVirtualResidentSmokeTestNative(
            String virtualBackingDir);
    private static native String runResidentSelfTestNative(
            String virtualBackingDir);
    private static native String runSelectiveRuntimeSelfTestNative(
            int iterations, String virtualBackingDir);
}
