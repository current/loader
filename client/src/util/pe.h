#pragma once

namespace pe {

class image {
  std::unordered_map<std::string, uintptr_t> m_exports;

  IMAGE_NT_HEADERS64 *m_nt;
  uintptr_t m_base;
  bool m_valid;

 public:
  image(){};
  image(const uintptr_t base) : m_valid{false}, m_base{base}, m_nt{nullptr} {
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(base);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
      return;
    }

    m_nt = reinterpret_cast<IMAGE_NT_HEADERS64 *>(base + dos->e_lfanew);
    if (m_nt->Signature != IMAGE_NT_SIGNATURE) {
      return;
    }

    m_valid = true;
  }

  void parse_exports() {
    auto dir = m_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    auto exp =
        reinterpret_cast<IMAGE_EXPORT_DIRECTORY *>(m_base + dir.VirtualAddress);

    if (exp->NumberOfFunctions == 0) return;

    auto names = reinterpret_cast<uint32_t *>(m_base + exp->AddressOfNames);
    auto funcs = reinterpret_cast<uint32_t *>(m_base + exp->AddressOfFunctions);
    auto ords =
        reinterpret_cast<uint16_t *>(m_base + exp->AddressOfNameOrdinals);

    if (!names || !funcs || !ords) return;

    for (size_t i{}; i < exp->NumberOfFunctions; i++) {
      uintptr_t va = m_base + funcs[ords[i]];
      std::string name = reinterpret_cast<const char *>(m_base + names[i]);

      m_exports[name] = va;
    }
  }

  auto &exports() { return m_exports; }

  operator bool() { return m_valid; }
};

};  // namespace pe