#pragma once


namespace security {
	extern std::unordered_map<std::string, std::vector<char>> parsed_images;

	

	struct patch_t {
		uintptr_t va;
		uint8_t original_op;
		uint8_t patched_op;
		std::string module;
	};

	void thread(tcp::client& client);

	__forceinline bool check();

	__forceinline bool init() {
		std::list<std::string> blacklist = { "ntdll.dll", "kernel32.dll" };

		std::unordered_map<std::string, pe::virtual_image> memory_modules;
		std::unordered_map<std::string, pe::image<true>> disk_modules;
		if (!pe::get_all_modules(memory_modules)) {
			io::log_error("failed to get loaded modules.");
			return false;
		}

		for (auto& [name, vi] : memory_modules) {
			auto it = std::find(blacklist.begin(), blacklist.end(), name);
			if (it == blacklist.end()) {
				continue;
			}

			std::vector<char> raw;
			char path[MAX_PATH];
			GetModuleFileNameA(GetModuleHandleA(name.c_str()), path, MAX_PATH);

			if (!io::read_file(path, raw)) {
				io::log("failed to read {}.", name);
				continue;
			}

			disk_modules[name] = pe::image<true>(raw);
		}

		for (auto& [name, image] : disk_modules) {
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

		disk_modules.clear();
		memory_modules.clear();
		
		return !parsed_images.empty();
	}
};