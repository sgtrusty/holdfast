// holdfast - the INI-style syntax shared by profiles and data files (data/lib, data/os)
#pragma once
#include "util/common.hpp"

namespace hf {

struct IniLine { std::string section, key, value; int no = 0; };

// [section], key = value, '#'/';' line comments, " #" inline comments. Sections and keys are lower-cased,
// keys may repeat. Throws ProfileError with origin:line on malformed input.
std::vector<IniLine> parse_ini(const std::string& text, const std::string& origin);

}  // namespace hf
