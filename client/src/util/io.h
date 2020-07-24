#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace io {
	extern std::shared_ptr<spdlog::logger> logger;

	void init();
	bool read_file(const std::string_view name, std::vector<char>& out);
};  // namespace io
