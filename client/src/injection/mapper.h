#pragma once

namespace mmap {
	void thread(tcp::client& client);

	void map32(tcp::client& client);
	void map64(tcp::client& client);
};