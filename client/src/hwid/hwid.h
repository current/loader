#pragma once
#include "../ui/ui.h"

namespace hwid {
	struct hwid_data_t {
		std::string gpu;

		uint64_t uid;
	};

	__forceinline bool fetch(hwid_data_t& out) {
		

		return true;
	}
};