#include "../include.h"
#include "../util/util.h"
#include "../client/client.h"
#include "../injection/process.h"
#include "../util/apiset.h"
#include "../util/syscalls.h"
#include "security.h"

#define SEC_NO_CHANGE 0x00400000

std::unordered_map<std::string, std::vector<char>> security::parsed_images;

void security::thread(tcp::client& client) {
	std::list<std::string> whitelist = { "d3dcompiler_43.dll", "xinput1_3.dll" };

	std::unordered_map<std::string, pe::virtual_image> images;
	std::unordered_map<std::string, pe::image<true>> raw_images;
	pe::get_all_modules(images);

	for (auto& [name, vi] : images) {
		auto it = std::find(whitelist.begin(), whitelist.end(), name);
		if (it != whitelist.end()) {
			continue;
		}

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

	while (client) {
		if (client.session_id.empty()) {
			continue;
		}

		std::unordered_map<std::string, pe::virtual_image> loaded_images;
		pe::get_all_modules(loaded_images);

		std::vector<patch_t> patches;
		for (auto& [name, limage] : loaded_images) {
			auto it = std::find(whitelist.begin(), whitelist.end(), name);
			if (it != whitelist.end()) {
				continue;
			}

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

				/*int ret = std::memcmp(&parsed[sec.va], reinterpret_cast<void*>(start + sec.va), sec.size);
				if (ret != 0) {
					io::log("found patch in {}.", name);
				}*/

				auto sec_start = reinterpret_cast<uint8_t*>(start + sec.va);
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
				}
			}
		}
		nlohmann::json j;

		j["patches"] = patches.size();

		/*const auto ret = client.write(tcp::packet_t(j.dump(), tcp::packet_type::write, client.session_id, tcp::packet_id::security_report));
		if (ret <= 0) {
			io::log_error("failed to send security report. {}", ret);

			client.shutdown();

			break;
		}*/

		std::this_thread::sleep_for(std::chrono::seconds(5));
	}
}