#pragma once
#include <string>

namespace hf::log {
void set_verbose(bool v);
bool verbose();
void debug(const std::string& m);
void info(const std::string& m);
void warn(const std::string& m);
void error(const std::string& m);
}  // namespace hf::log
