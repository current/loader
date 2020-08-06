#pragma once

#include "../util/native.h"

namespace pe {

#pragma pack(push, 4)
	struct reloc_entry_t {
		uint16_t                    offset : 12;
		uint16_t                    type : 4;
	};

	struct reloc_block_t {
		uint32_t                    base_rva;
		uint32_t                    size_block;
		reloc_entry_t               entries[1];   // Variable length array


		inline reloc_block_t* get_next() { return (reloc_block_t*)((char*)this + this->size_block); }
		inline uint32_t num_entries() { return (reloc_entry_t*)get_next() - &entries[0]; }
	};

	struct image_named_import_t
	{
		uint16_t            hint;
		char                name[1];
	};

#pragma pack(push, 8)
	struct image_thunk_data_x64_t
	{
		union
		{
			uint64_t        forwarder_string;
			uint64_t        function;
			uint64_t        address;                   // -> image_named_import_t
			struct
			{
				uint64_t    ordinal : 16;
				uint64_t    _reserved0 : 47;
				uint64_t    is_ordinal : 1;
			};
		};
	};
#pragma pack(pop)

	struct image_thunk_data_x86_t
	{
		union
		{
			uint32_t        forwarder_string;
			uint32_t        function;
			uint32_t        address;                   // -> image_named_import_t
			struct
			{
				uint32_t    ordinal : 16;
				uint32_t    _reserved0 : 15;
				uint32_t    is_ordinal : 1;
			};
		};
	};
#pragma pack(pop)

	template<bool x64,
		typename base_type = typename std::conditional<x64, image_thunk_data_x64_t, image_thunk_data_x86_t>::type>
	struct image_thunk_data_t : base_type {};

	template<bool x64, typename base_type = typename std::conditional<x64, IMAGE_NT_HEADERS64, IMAGE_NT_HEADERS32>::type>
	struct nt_headers_t : base_type {};

	struct import_t {
		std::string name;
		uint32_t rva;
	};

	struct section_t {
		std::string name;
		size_t size;
		size_t v_size;
		uint32_t rva;
		uint32_t va;
		uint32_t characteristics;
	};

	class virtual_image {
		std::unordered_map<std::string, uintptr_t> m_exports;
		std::vector<section_t> m_sections;

		IMAGE_NT_HEADERS64* m_nt;
		uintptr_t m_base;
	public:
		virtual_image() : m_nt{ nullptr }, m_base{ 0 } {};
		virtual_image(const std::string_view mod) : m_base{ 0 }, m_nt{ nullptr } {
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

					m_nt = reinterpret_cast<nt_headers_t<true>*>(m_base + dos->e_lfanew);

					parse_exports();
					break;
				}
			}
		}

		virtual_image(const uintptr_t base) : m_base{ base }, m_nt{ nullptr } {
			auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_base);

			m_nt = reinterpret_cast<nt_headers_t<true>*>(m_base + dos->e_lfanew);
		}

		void parse_sections() {
			auto secs = IMAGE_FIRST_SECTION(m_nt);
			const size_t n = m_nt->FileHeader.NumberOfSections;

			for (size_t i = 0; i < n; i++) {
				auto sec = secs[i];
				
				auto name = reinterpret_cast<const char*>(sec.Name);
				m_sections.emplace_back(section_t{ name, sec.SizeOfRawData, sec.Misc.VirtualSize, sec.PointerToRawData, sec.VirtualAddress, sec.Characteristics });
			}
		};

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
		auto &base() { return m_base; }
		auto& nt() { return m_nt; }
		auto& sections() { return m_sections; }

		operator bool() { return m_base != 0; }
	};

	template <bool x64 = false>
	class image {
		std::vector<char> m_buffer;

		std::unordered_map<std::string, std::vector<import_t>> m_imports;
		std::vector<section_t> m_sections;

		nt_headers_t<x64>* m_nt;
		IMAGE_DOS_HEADER* m_dos;
		std::vector<std::pair<uint32_t, reloc_entry_t>> m_relocs;

	public:
		image() = default;
		image(const std::vector<char>& buf) {
			m_buffer.assign(buf.begin(), buf.end());


			m_dos = reinterpret_cast<IMAGE_DOS_HEADER*>(m_buffer.data());
			m_nt = reinterpret_cast<nt_headers_t<x64>*>(m_buffer.data() + m_dos->e_lfanew);

			load();
		}

		void load() {
			parse_sections();
			parse_relocs();
			parse_imports();
		}

		void parse_sections() {
			auto secs = IMAGE_FIRST_SECTION(m_nt);
			const size_t n = m_nt->FileHeader.NumberOfSections;

			for (size_t i = 0; i < n; i++) {
				auto sec = secs[i];

				auto name = reinterpret_cast<const char*>(sec.Name);
				m_sections.emplace_back(section_t{ name, sec.SizeOfRawData, sec.Misc.VirtualSize, sec.PointerToRawData, sec.VirtualAddress });
			}
		};

		template<typename T = void*>
		T rva_to_ptr(const uint32_t rva) {
			uint8_t* output = rva + reinterpret_cast<uint8_t*>(m_dos);
			for (auto& sec : m_sections) {
				if (sec.va <= rva && rva < (sec.va + sec.v_size)) {
					output = output - sec.va + sec.rva;
					break;
				}
			}
			return reinterpret_cast<T>(output);
		}

		void parse_relocs() {
			const auto reloc_dir = m_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (!reloc_dir.Size) return;

			const auto ptr = rva_to_ptr(reloc_dir.VirtualAddress);
			auto block = reinterpret_cast<reloc_block_t*>(ptr);

			while (block->base_rva) {
				for (size_t i = 0; i < block->num_entries(); ++i) {
					auto entry = block->entries[i];

					m_relocs.emplace_back(std::make_pair(block->base_rva, entry));
				}
				block = block->get_next();
			}
		}

		void parse_imports() {
			const auto import_dir = m_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
			if (!import_dir.Size) return;

			const auto ptr = rva_to_ptr(import_dir.VirtualAddress);
			auto table = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(ptr);

			for (uint32_t i = 0; i < table->Name; i = table->Name, ++table) {
				auto mod_name = std::string(reinterpret_cast<char*>(rva_to_ptr(table->Name)));

				auto thunk = reinterpret_cast<image_thunk_data_t<x64>*>(rva_to_ptr(table->OriginalFirstThunk));

				auto step = x64 ? sizeof(uint64_t) : sizeof(uint32_t);
				for (uint32_t index = 0; thunk->address; index += step, ++thunk) {
					auto named_import = reinterpret_cast<image_named_import_t*>(rva_to_ptr(thunk->address));

					if (!thunk->is_ordinal) {
						import_t data;
						data.name = reinterpret_cast<const char*>(named_import->name);
						data.rva = table->OriginalFirstThunk + index;

						std::transform(mod_name.begin(), mod_name.end(), mod_name.begin(), ::tolower);

						m_imports[mod_name].emplace_back(std::move(data));
					}
				}
			}
		}

		void copy(std::vector<char>& out) {
			out.resize(m_nt->OptionalHeader.SizeOfImage);

			std::memcpy(&out[0], &m_buffer[0], m_nt->OptionalHeader.SizeOfHeaders);

			for (auto& sec : m_sections) {
				std::memcpy(&out[sec.va], &m_buffer[sec.rva], sec.size);
			}
		}

		void relocate(std::vector<char>& image, uintptr_t base) {
			const auto delta = base - m_nt->OptionalHeader.ImageBase;
			if (delta > 0) {
				for (auto& [base_rva, entry] : m_relocs) {
					if (x64) {
						if (entry.type == IMAGE_REL_BASED_HIGHLOW || entry.type == IMAGE_REL_BASED_DIR64) {
							*reinterpret_cast<uint64_t*>(&image[base_rva + entry.offset]) += delta;
						}
						continue;
					}

					if (entry.type == IMAGE_REL_BASED_HIGHLOW) {
						*reinterpret_cast<uint32_t*>(&image[base_rva + entry.offset]) += delta;
					}
				}
			}
		}

		operator bool() const { return m_nt != nullptr; }

		auto& imports() const { return m_imports; }
		auto& relocs() const { return m_relocs; }
		auto& sections() const { return m_sections; }
	};


	static virtual_image &ntdll() {
		static virtual_image img{};
		if (!img) {
			img = virtual_image("ntdll.dll");
		}
		return img;
	}

	bool get_all_modules(std::unordered_map<std::string, virtual_image>& modules);
};  // namespace pe