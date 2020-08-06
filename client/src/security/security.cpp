#include "../include.h"
#include "../util/util.h"
#include "../client/client.h"
#include "../injection/process.h"
#include "../util/apiset.h"
#include "../util/syscalls.h"
#include "security.h"

std::unordered_map<std::string, std::vector<char>> security::parsed_images;

void security::thread(tcp::client& client) {
	if (!init()) {
		io::log_error("failed to init security thread.");

		client.shutdown();

		return;
	}

	while (client) {
		if (client.session_id.empty()) {
			continue;
		}

		bool ret = check();
		io::log("check returned {}.", ret);

		std::unordered_map<std::string, pe::virtual_image> loaded_images;
		if (!pe::get_all_modules(loaded_images)) {
			io::log_error("failed to get loaded modules.");

			client.shutdown();

			break;
		}

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

__forceinline bool security::check() {
	static auto peb = util::peb();
	auto being_debugged = static_cast<bool>(peb->BeingDebugged);
	if (being_debugged) {
		return true;
	}

	io::log("being debugged {}", being_debugged);

	static auto query_info = g_syscalls.get<native::NtQueryInformationProcess>("NtQueryInformationProcess");

	uint32_t debug_inherit = 0;
	auto status = query_info(INVALID_HANDLE_VALUE, native::ProcessDebugFlags, &debug_inherit, sizeof(debug_inherit), 0);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to get local process debug flags, status {:#X}.", (status & 0xFFFFFFFF));
		return true;
	}

	io::log("debug inherit {}", debug_inherit);

	if (debug_inherit == 0) {
		return true;
	}

	uint64_t remote_debug = 0;
	status = query_info(INVALID_HANDLE_VALUE, native::ProcessDebugPort, &remote_debug, sizeof(remote_debug), 0);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to get local process debug port, status {:#X}.", (status & 0xFFFFFFFF));
		return true;
	}

	io::log("remote debug {}", remote_debug);
	if (remote_debug != 0) {
		return true;
	}

	return false;
}