#pragma once

#include <string>

namespace hookself {

std::string RunM0Probe();
std::string RunM1Observation();
std::string RunM2Redirect(const std::string& files_dir);
std::string RunM2MissingRedirect(const std::string& files_dir);

}  // namespace hookself
