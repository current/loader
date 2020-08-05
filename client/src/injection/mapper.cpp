#include "../include.h"
#include "../client/client.h"
#include "../util/util.h"
#include "process.h"
#include "mapper.h"

void mmap::thread(tcp::client& client) {
	while (client) {
		if (client.state != tcp::client_state::imports_ready) {
			std::this_thread::sleep_for(std::chrono::seconds(5));
			continue;
		}

		if (client.selected_game.x64) {
			map64(client);

			break;
		}

		map32(client);
		break;
	}
}

void mmap::map32(tcp::client& client) {
	client.state = tcp::client_state::waiting;

	std::vector<util::process_data_t> dat;
	if (!util::fetch_processes(dat)) {
		io::log_error("failed to fetch processes.");
		client.shutdown();
		return;
	}

	auto needle = std::find_if(dat.begin(), dat.end(), [&](util::process_data_t& dat) {
		return dat.name == client.selected_game.process_name;
	});

	io::log("waiting for {}.", client.selected_game.process_name);

	while (needle == dat.end()) {
		std::this_thread::sleep_for(std::chrono::seconds(5));
		if (!client) {
			return;
		}

		if (!util::fetch_processes(dat)) {
			io::log_error("failed to fetch processes.");
			client.shutdown();
			return;
		}

		needle = std::find_if(dat.begin(), dat.end(), [&](util::process_data_t& dat) {
			return dat.name == client.selected_game.process_name;
		});

		io::log(".");
	}

	io::log("found!");

	util::process<uint32_t> proc(*needle);

	if (!proc.open()) {
		client.shutdown();
		return;
	}

	if (!proc.enum_modules()) {
		io::log_error("failed to enum {} modules", proc.name());
		client.shutdown();
		return;
	}

	auto image = proc.allocate(client.mapper_data.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!image) {
		io::log_error("failed to allocate memory for image.");
		client.shutdown();
		return;
	}

	io::log("image base : {:x}", image);

	auto imports = nlohmann::json::parse(client.mapper_data.imports);

	nlohmann::json final_imports;
	for (auto& [key, value] : imports.items()) {
		for (auto& i : value) {
			auto name = i.get<std::string>();

			auto addr = proc.module_export(proc.map(key), name);

			io::log("{}->{}->{:x}", key, name, addr);

			final_imports[name] = addr;;
		}
	}
	imports.clear();

	nlohmann::json resp;
	resp["alloc"] = image;
	resp["id"] = client.selected_game.process_name;
	resp["x64"] = client.selected_game.x64;

	client.write(tcp::packet_t(resp.dump(), tcp::packet_type::write, client.session_id, tcp::packet_id::image));
	resp.clear();

	client.stream(final_imports.dump());
	final_imports.clear();

	io::log("please wait...");
	while (client.state != tcp::client_state::image_ready) {
		if (!client) {
			return;
		}

		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	if (!proc.write(image, client.mapper_data.image.data(), client.mapper_data.image.size())) {
		io::log_error("failed to write image.");
		client.shutdown();
		return;
	}
	client.mapper_data.image.clear();

	auto entry = image + client.mapper_data.entry;

	io::log("entry : {:x}", entry);

	static std::vector<uint8_t> shellcode = { 0x55, 0x89, 0xE5, 0x6A, 0x00, 0x6A, 0x01, 0x68, 0xEF, 0xBE,
		0xAD, 0xDE, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xD0, 0x89, 0xEC, 0x5D, 0xC3 };

	*reinterpret_cast<uint32_t*>(&shellcode[8]) = image;
	*reinterpret_cast<uint32_t*>(&shellcode[13]) = entry;

	auto code = proc.allocate(shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!proc.write(code, shellcode.data(), shellcode.size())) {
		io::log_error("failed to write shellcode.");
		client.shutdown();

		return;
	}

	io::log("shellcode : {:x}", code);

	proc.thread(code);

	proc.free(code, shellcode.size());

	proc.close();

	client.state = tcp::client_state::injected;

	io::log("done");

	std::this_thread::sleep_for(std::chrono::seconds(3));

	client.shutdown();
}

void mmap::map64(tcp::client& client) {
	client.state = tcp::client_state::waiting;

	std::vector<util::process_data_t> dat;
	if (!util::fetch_processes(dat)) {
		io::log_error("failed to fetch processes.");
		client.shutdown();
		return;
	}

	auto needle = std::find_if(dat.begin(), dat.end(), [&](util::process_data_t& dat) {
		return dat.name == client.selected_game.process_name;
	});

	io::log("waiting for {}.", client.selected_game.process_name);
	while (needle == dat.end()) {
		std::this_thread::sleep_for(std::chrono::seconds(5));

		if (!client) {
			return;
		}

		if (!util::fetch_processes(dat)) {
			io::log_error("failed to fetch processes.");
			client.shutdown();
			return;
		}

		needle = std::find_if(dat.begin(), dat.end(), [&](util::process_data_t& dat) {
			return dat.name == client.selected_game.process_name;
		});

		io::log(".");
	}

	io::log("found!");

	util::process<uint64_t> proc(*needle);

	if (!proc.open()) {
		client.shutdown();
		return;
	}

	if (!proc.enum_modules()) {
		io::log_error("failed to enum {} modules", proc.name());

		client.shutdown();

		return;
	}

	auto image = proc.allocate(client.mapper_data.image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!image) {
		io::log_error("failed to allocate memory for image.");
		client.shutdown();
		return;
	}

	io::log("image base : {:x}", image);

	auto imports = nlohmann::json::parse(client.mapper_data.imports);

	nlohmann::json final_imports;
	for (auto& [key, value] : imports.items()) {
		for (auto& i : value) {
			auto name = i.get<std::string>();

			auto addr = proc.module_export(proc.map(key), name);

			io::log("{}->{}->{:x}", key, name, addr);

			final_imports[name] = addr;
		}
	}
	imports.clear();

	nlohmann::json resp;
	resp["alloc"] = image;
	resp["id"] = client.selected_game.process_name;
	resp["x64"] = client.selected_game.x64;

	client.write(tcp::packet_t(resp.dump(), tcp::packet_type::write, client.session_id, tcp::packet_id::image));
	resp.clear();

	client.stream(final_imports.dump());
	final_imports.clear();

	io::log("please wait...");
	while (client.state != tcp::client_state::image_ready) {
		if (!client) {
			return;
		}
		
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	if (!proc.write(image, client.mapper_data.image.data(), client.mapper_data.image.size())) {
		io::log_error("failed to write image.");
		client.shutdown();
		return;
	}
	client.mapper_data.image.clear();

	auto entry = image + client.mapper_data.entry;

	io::log("entry : {:x}", entry);

	static std::vector<uint8_t> shellcode = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0xC2,0x01, 0x00, 0x00, 0x00, 0x4D, 0x31, 0xC0,
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3 };

	*reinterpret_cast<uint64_t*>(&shellcode[6]) = image;
	*reinterpret_cast<uint64_t*>(&shellcode[26]) = entry;

	auto code = proc.allocate(shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!proc.write(code, shellcode.data(), shellcode.size())) {
		io::log_error("failed to write shellcode.");
		client.shutdown();
		return;
	}

	io::log("shellcode : {:x}", code);

	proc.thread(code);

	proc.free(code, shellcode.size());

	proc.close();

	client.state = tcp::client_state::injected;

	io::log("done");

	std::this_thread::sleep_for(std::chrono::seconds(3));

	client.shutdown();
}