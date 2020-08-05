#pragma once

#include <fmt/format.h>
#include <fmt/color.h>

#include "../client/enc.h"



namespace io {
	extern std::mutex file_mutex;

	template<typename... Args>
	void log(const std::string_view str, Args... params) {
		static auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(handle, FOREGROUND_GREEN);
		fmt::print("$> ");
		SetConsoleTextAttribute(handle, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

		std::string msg{str};
		msg.append("\n");

		fmt::print(msg, std::forward<Args>(params)...);
	}

	template<typename... Args>
	void log_error(const std::string_view str, Args... params) {
		static auto handle = GetStdHandle(STD_OUTPUT_HANDLE);
		SetConsoleTextAttribute(handle, FOREGROUND_RED);
		fmt::print("$> ");
		SetConsoleTextAttribute(handle, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

		std::string msg{str};
		msg.append("\n");

		fmt::print(msg, std::forward<Args>(params)...);
	}

	bool read_file(const std::string_view path, std::vector<char>& out);
};  // namespace io
