// holdfast - common types and string/path helpers
#pragma once
#include <cstdint>
#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace hf {
namespace fs = std::filesystem;
using Strings = std::vector<std::string>;

struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
struct ProfileError : Error { using Error::Error; };
struct PolicyError : Error { using Error::Error; };

template <class... A> std::string cat(const A&... a) {
    std::ostringstream o;
    (o << ... << a);
    return o.str();
}

std::string trim(std::string_view s);
std::string lower(std::string s);
Strings split_ws(std::string_view s);      // plain whitespace split
Strings split_words(std::string_view s);   // shell-ish: '..', "..", backslash
std::string shell_quote(std::string_view s);
std::string join(const Strings& v, std::string_view sep);
bool is_hex(std::string_view s, size_t len);

// Lexically normalise: collapse "..", ".", duplicate and trailing slashes.
fs::path norm(const fs::path& p);
// True if p == base or p lies inside base (component-wise, lexical).
bool path_under(const fs::path& p, const fs::path& base);
// weakly_canonical (resolves symlinks of existing prefix) then norm.
fs::path canon(const fs::path& p);
}  // namespace hf
