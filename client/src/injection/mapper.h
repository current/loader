#pragma once

namespace mmap {

	void thread(tcp::client& client) {
		while (client.mapper_data.imports.empty()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}



	}

};