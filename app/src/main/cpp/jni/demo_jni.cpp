#include <jni.h>

#include <string>

#include "demo_runtime.h"

namespace {

using DemoAction = std::string (*)();

jstring RunDemoAction(JNIEnv* env, DemoAction action, const char* fallback) {
    try {
        const std::string report = action();
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(fallback);
    }
}

}  // namespace

extern "C" JNIEXPORT jboolean JNICALL
Java_com_io_hookself_MainActivity_isSelfAttachedForLogging(
        JNIEnv*, jobject) {
    return hookself::demo::IsAttached() ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_MainActivity_attachSelfForLogging(
        JNIEnv* env, jobject) {
    return RunDemoAction(
            env, hookself::demo::AttachSelf,
            "HOOKSELF_DEMO_ATTACH {\"verdict\":\"INTERNAL_ERROR\"}");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_MainActivity_openStatProcStatusForLogging(
        JNIEnv* env, jobject) {
    return RunDemoAction(
            env, hookself::demo::OpenStatProcStatus,
            "HOOKSELF_DEMO_OPEN_STAT {\"verdict\":\"INTERNAL_ERROR\"}");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_MainActivity_runPtraceDetectionForLogging(
        JNIEnv* env, jobject) {
    return RunDemoAction(
            env, hookself::demo::RunPtraceDetection,
            "HOOKSELF_DEMO_PTRACE {\"verdict\":\"INTERNAL_ERROR\"}");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_MainActivity_runAntiDebugForLogging(
        JNIEnv* env, jobject) {
    return RunDemoAction(
            env, hookself::demo::RunAntiDebug,
            "HOOKSELF_DEMO_ANTIDEBUG {\"verdict\":\"INTERNAL_ERROR\"}");
}
