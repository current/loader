#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

namespace io {
	extern std::shared_ptr<spdlog::logger> logger;

	void init();
};  // namespace io
