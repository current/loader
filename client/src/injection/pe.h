#pragma once

namespace pe {

	class virtual_image {
		std::unordered_map<std::string, uintptr_t> m_exports;

		IMAGE_NT_HEADERS64* m_nt;
		uintptr_t m_base;
	public:
		virtual_image() : m_nt{ nullptr }, m_base{ 0 } {};
		virtual_image(const std::string_view mod) {
			auto peb = util::peb();
			if (!peb) return;

			if (!peb->Ldr->InMemoryOrderModuleList.Flink) return;

			auto* list = &peb->Ldr->InMemoryOrderModuleList;

			for (auto i = list->Flink; i != list; i = i->Flink) {
				auto entry = CONTAINING_RECORD(i, native::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
				if (!entry)
					continue;

				auto name = util::wide_to_multibyte(entry->BaseDllName.Buffer);
				std::transform(name.begin(), name.end(), name.begin(), ::tolower);

				if (name == mod) {
					m_base = uintptr_t(entry->DllBase);
					auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_base);

					m_nt = reinterpret_cast<native::nt_headers_t<true>*>(m_base + dos->e_lfanew);

					parse_exports();
					break;
				}
			}
		}

		void parse_exports() {
			auto dir = m_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			auto exp =
				reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(m_base + dir.VirtualAddress);

			if (exp->NumberOfFunctions == 0) return;

			auto names = reinterpret_cast<uint32_t*>(m_base + exp->AddressOfNames);
			auto funcs = reinterpret_cast<uint32_t*>(m_base + exp->AddressOfFunctions);
			auto ords = reinterpret_cast<uint16_t*>(m_base + exp->AddressOfNameOrdinals);

			if (!names || !funcs || !ords) return;

			for (size_t i{}; i < exp->NumberOfFunctions; i++) {
				uintptr_t va = m_base + funcs[ords[i]];
				std::string name = reinterpret_cast<const char*>(m_base + names[i]);

				m_exports[name] = va;
			}
		}

		auto& exports() { return m_exports; }
		operator bool() { return m_base != 0; }
	};

};  // namespace pe