#include "core/elf.hpp"

#include <elf.h>

#include <cstring>
#include <fstream>

static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "ELF reader assumes a little-endian host");

namespace hf {

namespace {

constexpr uint64_t kMaxDyn = 1u << 20, kMaxStr = 16u << 20;

struct Reader {
    std::ifstream f;
    explicit Reader(const fs::path& p) : f(p, std::ios::binary) {}
    bool at(uint64_t off, void* dst, size_t n) {
        f.clear();
        f.seekg(static_cast<std::streamoff>(off));
        f.read(static_cast<char*>(dst), static_cast<std::streamsize>(n));
        return static_cast<size_t>(f.gcount()) == n;
    }
};

std::string cstr(const std::string& tab, uint64_t off) {
    if (off >= tab.size()) throw Error("corrupt ELF string table");
    size_t end = tab.find('\0', static_cast<size_t>(off));
    if (end == std::string::npos) throw Error("corrupt ELF string table");
    return tab.substr(static_cast<size_t>(off), end - static_cast<size_t>(off));
}

}  // namespace

std::optional<unsigned> elf_abi(const fs::path& file) {
    std::ifstream f(file, std::ios::binary);
    unsigned char h[20];
    if (!f || !f.read(reinterpret_cast<char*>(h), sizeof h) || std::memcmp(h, ELFMAG, SELFMAG) != 0) return std::nullopt;
    const unsigned machine = h[EI_DATA] == ELFDATA2MSB ? (unsigned{h[18]} << 8 | h[19]) : (unsigned{h[19]} << 8 | h[18]);
    return (unsigned{h[EI_CLASS]} << 16) | machine;
}

std::optional<ElfDeps> read_elf_deps(const fs::path& file) {
    Reader r(file);
    if (!r.f) throw Error("cannot open " + file.string());
    unsigned char id[EI_NIDENT];
    if (!r.at(0, id, sizeof id) || std::memcmp(id, ELFMAG, SELFMAG) != 0) return std::nullopt;
    const std::string hint = "; use `libs = full` in [fs] for this profile";
    if (id[EI_CLASS] != ELFCLASS64 || id[EI_DATA] != ELFDATA2LSB)
        throw Error("unsupported ELF (only 64-bit little-endian is analysed): " + file.string() + hint);
    Elf64_Ehdr eh;
    if (!r.at(0, &eh, sizeof eh) || eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum > 512)
        throw Error("unreadable ELF header: " + file.string() + hint);

    ElfDeps out;
    std::vector<Elf64_Phdr> loads;
    Elf64_Phdr dyn{};
    bool has_dyn = false;
    for (unsigned i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr ph;
        if (!r.at(eh.e_phoff + uint64_t{i} * sizeof ph, &ph, sizeof ph)) throw Error("truncated ELF: " + file.string());
        if (ph.p_type == PT_LOAD) loads.push_back(ph);
        else if (ph.p_type == PT_DYNAMIC) { dyn = ph; has_dyn = true; }
        else if (ph.p_type == PT_INTERP && ph.p_filesz > 1 && ph.p_filesz < 4096) {
            std::string s(ph.p_filesz, '\0');
            if (!r.at(ph.p_offset, s.data(), s.size())) throw Error("truncated ELF: " + file.string());
            out.interp = s.substr(0, s.find('\0'));
        }
    }
    if (!has_dyn) return out;                                  // static binary
    if (dyn.p_filesz > kMaxDyn) throw Error("oversized dynamic section: " + file.string());

    std::vector<Elf64_Dyn> d(dyn.p_filesz / sizeof(Elf64_Dyn));
    if (!d.empty() && !r.at(dyn.p_offset, d.data(), d.size() * sizeof(Elf64_Dyn))) throw Error("truncated ELF: " + file.string());
    uint64_t strtab = 0, strsz = 0;
    std::vector<uint64_t> needed, search;
    for (const Elf64_Dyn& e : d) {
        if (e.d_tag == DT_NULL) break;
        if (e.d_tag == DT_NEEDED) needed.push_back(e.d_un.d_val);
        else if (e.d_tag == DT_RPATH || e.d_tag == DT_RUNPATH) search.push_back(e.d_un.d_val);
        else if (e.d_tag == DT_STRTAB) strtab = e.d_un.d_ptr;
        else if (e.d_tag == DT_STRSZ) strsz = e.d_un.d_val;
    }
    if (needed.empty() && search.empty()) return out;
    if (!strtab || !strsz || strsz > kMaxStr) throw Error("missing ELF string table: " + file.string());

    // DT_STRTAB is a virtual address; translate through the PT_LOAD segment that contains it.
    uint64_t off = 0;
    bool mapped = false;
    for (const Elf64_Phdr& l : loads)
        if (strtab >= l.p_vaddr && strtab < l.p_vaddr + l.p_filesz) { off = l.p_offset + (strtab - l.p_vaddr); mapped = true; break; }
    if (!mapped) throw Error("cannot map ELF string table: " + file.string());
    std::string tab(strsz, '\0');
    if (!r.at(off, tab.data(), tab.size())) throw Error("truncated ELF: " + file.string());

    for (uint64_t o : needed) out.needed.push_back(cstr(tab, o));
    for (uint64_t o : search) {
        std::string s = cstr(tab, o);
        size_t a = 0;
        while (a <= s.size()) {
            size_t b = s.find(':', a);
            if (b == std::string::npos) b = s.size();
            if (b > a) out.search.push_back(s.substr(a, b - a));
            a = b + 1;
        }
    }
    return out;
}

}  // namespace hf
