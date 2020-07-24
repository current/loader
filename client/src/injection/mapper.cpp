#include "../include.h"
#include "../client/client.h"
#include "../util/util.h"
#include "process.h"
#include "mapper.h"

void mmap::thread(tcp::client& client) {
	while (client.mapper_data.imports.empty()) {
		std::this_thread::sleep_for(std::chrono::seconds(2));
	}

	std::vector<util::process> process_list;
	util::fetch_processes(process_list);

	auto needle = std::find_if(process_list.begin(), process_list.end(), [&](util::process& proc) {
		return proc.name() == "notepad++.exe";
	});

	while (needle == process_list.end()) {
		std::this_thread::sleep_for(std::chrono::seconds(2));

		util::fetch_processes(process_list);

		io::logger->info("size {}", process_list.size());

		io::logger->info("waiting for process..");

		needle = std::find_if(process_list.begin(), process_list.end(), [&](util::process& proc) {
			return proc.name() == "notepad++.exe";
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

		auto base = needle->load(key);
		if (!base) {
			io::logger->error("failed to load {}", key);
			continue;
		}

		for (auto& i : value) {
			auto name = i.get<std::string>();

			final_imports[name] = needle->module_export(base, name);
		}
	}

	nlohmann::json resp;
	resp["alloc"] = image;

	client.write(tcp::packet_t(resp.dump(), tcp::packet_type::write, client.session_id, tcp::packet_id::image));

	auto proc_imports = final_imports.dump();
	client.stream(proc_imports);

	proc_imports.clear();
	final_imports.clear();
	imports.clear();
	client.mapper_data.imports.clear();

	io::logger->info("please wait...");
	while (client.mapper_data.image.size() != client.mapper_data.image_size) {
		std::this_thread::sleep_for(std::chrono::seconds(2));
	}

	if (!needle->write(image, client.mapper_data.image.data(), client.mapper_data.image.size())) {
		io::logger->error("failed to write image.");
		return;
	}

	client.mapper_data.image.clear();

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

	client.shutdown();

	client.state = tcp::client_state::injected;
}