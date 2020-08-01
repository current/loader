#include "../include.h"
#include "../util/util.h"
#include "../client/client.h"
#include "../injection/process.h"
#include "../util/apiset.h"
#include "security.h"

void security::thread(tcp::client& client) {
	std::unordered_map<std::string, pe::image<true>> raw_images;
	std::unordered_map<std::string, std::vector<char>> parsed_images;

	std::unordered_map<std::string, pe::virtual_image> images;
	pe::get_all_modules(images);
	for (auto& [name, vi] : images) {
		std::vector<char> raw;
		char path[MAX_PATH];
		GetModuleFileNameA(GetModuleHandleA(name.c_str()), path, MAX_PATH);

		if (!io::read_file(path, raw)) {
			io::log("failed to read {}.", name);
			continue;
		}

		raw_images[name] = pe::image<true>(raw);
	}

	for (auto& [name, image] : raw_images) {
		std::vector<char> mem;

		image.copy(mem);
		image.relocate(mem, uintptr_t(GetModuleHandleA(name.c_str())));

		for (auto& [mod, funcs] : image.imports()) {
			std::string mod_name{ mod };
			g_apiset.find(mod_name);

			for (auto& func : funcs) {
				*reinterpret_cast<uintptr_t*>(&mem[func.rva]) = uintptr_t(GetProcAddress(GetModuleHandleA(mod_name.c_str()), func.name.c_str()));
			}
		}

		parsed_images[name] = mem;
	}

	raw_images.clear();
	images.clear();

	while (1) {
		std::unordered_map<std::string, pe::virtual_image> loaded_images;
		pe::get_all_modules(loaded_images);

		std::vector<patch_t> patches;
		for (auto& [name, limage] : loaded_images) {
			auto& parsed = parsed_images[name];
			if (parsed.empty()) {
				continue;
			}

			auto start = limage.base();
			auto len = limage.nt()->OptionalHeader.SizeOfImage;


			limage.parse_sections();
			for (auto& sec : limage.sections()) {
				if (sec.name != ".text") {
					continue;
				}


				int ret = std::memcmp(&parsed[sec.va], reinterpret_cast<void*>(start + sec.va), sec.size);
				if (ret != 0) {
					io::log("found patch in {}.", name);
				}

				/*auto sec_start = reinterpret_cast<uint8_t*>(start + sec.va);
				auto sec_len = sec.size;

				for (size_t i = 0; i < sec_len; ++i) {
					auto va = start + sec.va + i;
					auto og_op = uint8_t(parsed[sec.va + i]);
					auto cur_op = sec_start[i];

					if (og_op != cur_op) {
						patch_t patch;
						patch.va = va;
						patch.original_op = og_op;
						patch.patched_op = cur_op;
						patch.module = name;

						patches.emplace_back(patch);
					}
				}*/
			}
		}

		for (auto& patch : patches) {
			io::log("found patch in {} at {:x}.", patch.module, patch.va);
		}

		std::this_thread::sleep_for(std::chrono::seconds(5));
	}
}
