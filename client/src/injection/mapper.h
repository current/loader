#pragma once


namespace mmap {
	struct header {
		size_t image_size;
		uint32_t entry;
		uint32_t base;
	};
};