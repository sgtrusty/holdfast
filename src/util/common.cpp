#include "util/common.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <cctype>

namespace hf {

std::string trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

Strings split_ws(std::string_view s) {
    Strings out;
    std::string cur;
    for (char c : s) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            if (!cur.empty()) out.push_back(std::move(cur)), cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

Strings split_words(std::string_view s) {
    Strings out;
    std::string cur;
    bool have = false;
    char quote = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (quote == '\'') {
            if (c == '\'') quote = 0; else cur.push_back(c);
        } else if (quote == '"') {
            if (c == '"') quote = 0;
            else if (c == '\\' && i + 1 < s.size() && (s[i + 1] == '"' || s[i + 1] == '\\')) cur.push_back(s[++i]);
            else cur.push_back(c);
        } else if (c == '\'' || c == '"') {
            quote = c; have = true;
        } else if (c == '\\' && i + 1 < s.size()) {
            cur.push_back(s[++i]); have = true;
        } else if (std::isspace(static_cast<unsigned char>(c))) {
            if (have || !cur.empty()) out.push_back(cur);
            cur.clear(); have = false;
        } else {
            cur.push_back(c); have = true;
        }
    }
    if (quote) throw Error("unterminated quote in: " + std::string(s));
    if (have || !cur.empty()) out.push_back(cur);
    return out;
}

std::string shell_quote(std::string_view s) {
    if (!s.empty() && s.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-+=:,./@%") == std::string_view::npos)
        return std::string(s);
    std::string o = "'";
    for (char c : s) { if (c == '\'') o += "'\\''"; else o.push_back(c); }
    return o + "'";
}

std::string join(const Strings& v, std::string_view sep) {
    std::string o;
    for (size_t i = 0; i < v.size(); ++i) { if (i) o += sep; o += v[i]; }
    return o;
}

bool is_hex(std::string_view s, size_t len) {
    if (s.size() != len) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c); });
}

bool is_ipv4_unicast(const std::string& s) {
    in_addr a{};
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;     // strict dotted quad: no "1.1", no spaces, no IPv6
    const unsigned first = ntohl(a.s_addr) >> 24;
    return first != 0 && first < 224;
}

fs::path norm(const fs::path& p) {
    fs::path n = p.lexically_normal();
    if (n.has_relative_path() && n.filename().empty()) n = n.parent_path();
    return n;
}

bool path_under(const fs::path& p, const fs::path& base) {
    fs::path a = norm(p), b = norm(base);
    auto pi = a.begin();
    for (auto bi = b.begin(); bi != b.end(); ++bi, ++pi) {
        if (pi == a.end() || *pi != *bi) return false;
    }
    return true;
}

fs::path canon(const fs::path& p) {
    std::error_code ec;
    fs::path c = fs::weakly_canonical(p, ec);
    return norm(ec ? p : c);
}

}  // namespace hf
