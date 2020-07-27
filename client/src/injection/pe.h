#pragma once

#include <linux-pe/linuxpe>


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

	struct import_t {
		std::string name;
		uint32_t rva;
	};

	struct section_t {
		std::string name;
		size_t size;
		uint32_t rva;
		uint32_t va;
	};

	template <bool x64 = false>
	class image {
		win::image_t<x64>* m_image;
		std::vector<char> m_buffer;

		std::unordered_map<std::string, std::vector<import_t>> m_imports;
		std::vector<section_t> m_sections;
		std::vector<std::pair<uint32_t, win::reloc_entry_t>> m_relocs;

	public:
		image() = default;
		image(const std::vector<char>& buf) : m_image{ nullptr } {
			m_buffer.assign(buf.begin(), buf.end());

			m_image = reinterpret_cast<win::image_t<x64>*>(m_buffer.data());
			load();
		}

		void load() {
			parse_sections();
			parse_relocs();
			parse_imports();
		}

		void parse_sections() {
			const auto nt = m_image->get_nt_headers();
			const size_t n = nt->file_header.num_sections;

			for (size_t i = 0; i < n; i++) {
				auto section = nt->get_section(i);
				m_sections.emplace_back(section_t{ section->name, section->size_raw_data,
					section->ptr_raw_data,
					section->virtual_address });
			}
		};

		void parse_relocs() {
			const auto reloc_dir =
				m_image->get_directory(win::directory_id::directory_entry_basereloc);
			if (!reloc_dir) return;

			const auto ptr = m_image->rva_to_ptr(reloc_dir->rva);
			auto block = reinterpret_cast<win::reloc_block_t*>(ptr);

			while (block->base_rva) {
				for (size_t i = 0; i < block->num_entries(); ++i) {
					auto entry = block->entries[i];

					m_relocs.emplace_back(std::make_pair(block->base_rva, entry));
				}
				block = block->get_next();
			}
		}

		void parse_imports() {
			const auto import_dir =
				m_image->get_directory(win::directory_id::directory_entry_import);
			if (!import_dir) return;

			const auto ptr = m_image->rva_to_ptr(import_dir->rva);
			auto table = reinterpret_cast<win::import_directory_t*>(ptr);

			for (uint32_t previous_name = 0; previous_name < table->rva_name;
				previous_name = table->rva_name, ++table) {
				auto name_ptr = m_image->rva_to_ptr(table->rva_name);
				auto mod_name = std::string(reinterpret_cast<char*>(name_ptr));

				auto thunk = reinterpret_cast<win::image_thunk_data_t<x64>*>(
					m_image->rva_to_ptr(table->rva_original_first_thunk));

				auto step = x64 ? sizeof(uint64_t) : sizeof(uint32_t);
				for (uint32_t index = 0; thunk->address; index += step, ++thunk) {
					auto named_import = reinterpret_cast<win::image_named_import_t*>(
						m_image->rva_to_ptr(thunk->address));

					if (!thunk->is_ordinal) {
						import_t data;
						data.name = reinterpret_cast<const char*>(named_import->name);
						data.rva = table->rva_first_thunk + index;

						std::transform(mod_name.begin(), mod_name.end(), mod_name.begin(),
							::tolower);

						m_imports[mod_name].emplace_back(std::move(data));
					}
				}
			}
		}

		void copy(std::vector<char>& out) {
			const auto nt = m_image->get_nt_headers();
			const auto n = nt->file_header.num_sections;

			out.resize(nt->optional_header.size_image);

			std::memcpy(&out[0], &m_buffer[0], 4096);

			for (auto& sec : m_sections) {
				std::memcpy(&out[sec.va], &m_buffer[sec.rva], sec.size);
			}
		}

		void relocate(std::vector<char>& image, uintptr_t base) {
			const auto delta =
				base - m_image->get_nt_headers()->optional_header.image_base;
			if (delta > 0) {
				for (auto& [base_rva, entry] : m_relocs) {
					if (x64) {
						if (entry.type == win::rel_based_high_low ||
							entry.type == win::rel_based_dir64) {
							*reinterpret_cast<uint64_t*>(image.data() + base_rva +
								entry.offset) += delta;
						}
						continue;
					}

					if (entry.type == win::rel_based_high_low) {
						*reinterpret_cast<uint32_t*>(image.data() + base_rva +
							entry.offset) += delta;
					}
				}
			}
		}

		const auto operator->() { return m_image; }
		operator bool() const { return m_image != nullptr; }

		auto& imports() const { return m_imports; }
		auto& relocs() const { return m_relocs; }
		auto& sections() const { return m_sections; }
	};
};  // namespace pe