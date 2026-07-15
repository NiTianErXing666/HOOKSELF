#include <jni.h>

#include <string>

#include "demo_runtime.h"

extern "C" JNIEXPORT jstring JNICALL
Java_com_io_hookself_NativeTestBridge_detachDemo(
        JNIEnv* env, jclass) {
    try {
        const std::string report = hookself::demo::DetachSelf();
        return env->NewStringUTF(report.c_str());
    } catch (...) {
        return env->NewStringUTF(
                "HOOKSELF_DEMO_DETACH {\"verdict\":\"INTERNAL_ERROR\"}");
    }
}
