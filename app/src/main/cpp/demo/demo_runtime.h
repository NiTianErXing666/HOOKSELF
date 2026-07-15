#pragma once

#include <string>

namespace hookself::demo {

bool IsAttached() noexcept;
std::string AttachSelf();
std::string OpenStatProcStatus();
std::string RunPtraceDetection();
#if defined(HOOKSELF_DEMO_BUILD_TEST_SUPPORT)
std::string DetachSelf();
#endif

}  // namespace hookself::demo
