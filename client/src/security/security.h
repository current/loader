#pragma once


namespace security {
	extern std::unordered_map<std::string, std::vector<char>> parsed_images;

	struct patch_t {
		uintptr_t va;
		uint8_t original_op;
		uint8_t patched_op;
		std::string module;
	};

	void thread(tcp::client &client);
};