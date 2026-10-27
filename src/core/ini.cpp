#include "core/ini.hpp"

#include <sstream>

namespace hf {

std::vector<IniLine> parse_ini(const std::string& text, const std::string& origin) {
    std::vector<IniLine> out;
    std::stringstream ss(text);
    std::string raw, section;
    int no = 0;
    while (std::getline(ss, raw)) {
        ++no;
        std::string l = trim(raw);
        if (l.empty() || l[0] == '#' || l[0] == ';') continue;
        if (l.front() == '[') {
            if (l.back() != ']') throw ProfileError(cat(origin, ":", no, ": malformed section header"));
            section = lower(trim(l.substr(1, l.size() - 2)));
            continue;
        }
        auto eq = l.find('=');
        if (eq == std::string::npos) throw ProfileError(cat(origin, ":", no, ": expected key = value"));
        if (section.empty()) throw ProfileError(cat(origin, ":", no, ": key outside any section"));
        std::string val = l.substr(eq + 1);
        // Inline comment: whitespace followed by '#'. (A '#' glued to text is data.)
        for (size_t i = 0; i + 1 < val.size(); ++i)
            if (std::isspace(static_cast<unsigned char>(val[i])) && val[i + 1] == '#') { val.erase(i); break; }
        out.push_back({section, lower(trim(l.substr(0, eq))), trim(val), no});
    }
    return out;
}

}  // namespace hf
