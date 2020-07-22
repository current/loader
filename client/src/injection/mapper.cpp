#include "../include.h"
#include "../client/client.h"
#include "../util/util.h"
#include "process.h"
#include "mapper.h"

void mmap::thread(tcp::client& client) {
	while (client.mapper_data.imports.empty()) {
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}

	util::fetch_processes();

	auto needle = std::find_if(util::process_list.begin(), util::process_list.end(), [&](util::process& proc) {
		return strcmp(proc.name().c_str(), "notepad++.exe") == 0;
	});

	while (needle == util::process_list.end()) {
		std::this_thread::sleep_for(std::chrono::seconds(5));

		util::fetch_processes();
		
		io::logger->info("size {}", util::process_list.size());

		io::logger->info("waiting for process..");

		needle = std::find_if(util::process_list.begin(), util::process_list.end(), [&](util::process& proc) {
			return strcmp(proc.name().c_str(), "notepad++.exe") == 0;
		});
	}

	if (!needle->open()) {
		return;
	}

	if (!needle->enum_modules()) {
		io::logger->error("failed to enum {} modules", needle->name());
		return;
	}

	auto image = needle->allocate(client.mapper_data.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!image) {
		io::logger->error("failed to allocate memory for image.");
		return;
	}

	io::logger->info("image base : {:x}", image);

	auto imports = nlohmann::json::parse(client.mapper_data.imports);

	nlohmann::json final_imports;
	for (auto& [key, value] : imports.items()) {
		auto mod = key;
		std::transform(mod.begin(), mod.end(), mod.begin(), ::tolower);

		auto base = needle->load(mod);
		if (!base) {
			io::logger->error("failed to load {}", mod);
			continue;
		}

		for (auto& i : value) {
			auto name = i.get<std::string>();

			auto func = needle->module_export(mod, name);

			final_imports[name] = func;
		}
	}

	nlohmann::json resp;
	resp["alloc"] = image;

	client.write(tcp::packet_t(resp.dump(), tcp::packet_type::write, client.session_id, tcp::packet_id::image));

	auto proc_imports = final_imports.dump();
	client.stream(proc_imports);

	io::logger->info("please wait...");
	while (client.mapper_data.image.empty()) {
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	if (!needle->write(image, client.mapper_data.image.data(), client.mapper_data.image.size())) {
		io::logger->error("failed to write image.");
		return;
	}

	auto entry = image + client.mapper_data.entry;

	io::logger->info("entry : {:x}", entry);

	static std::vector<uint8_t> shellcode = { 0x55, 0x89, 0xE5, 0x6A, 0x00, 0x6A, 0x01, 0x68, 0xEF, 0xBE,
		0xAD, 0xDE, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xD0, 0x89, 0xEC, 0x5D, 0xC3 };

	*reinterpret_cast<uint32_t*>(&shellcode[8]) = image;
	*reinterpret_cast<uint32_t*>(&shellcode[13]) = entry;

	auto code = needle->allocate(shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!needle->write(code, shellcode.data(), shellcode.size())) {
		io::logger->error("failed to write shellcode.");
		return;
	}

	io::logger->info("shellcode : {:x}", code);

	needle->thread(code);

	needle->free(code, shellcode.size());

	needle->close();

	io::logger->info("done");

	client.state = tcp::client_state::injected;
}