#pragma once


namespace security {
	struct patch_t {
		uintptr_t va;
		uint8_t original_op;
		uint8_t patched_op;
		std::string module;
	};

	void thread(tcp::client &client);
};