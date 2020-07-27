#pragma once

#include <fmt/format.h>
#include <fmt/color.h>


namespace io {
	template<typename... Args>
	void log(const std::string_view str, Args... params) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN);
		fmt::print("$> ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

		std::string msg{str};
		msg.append("\n");

		fmt::print(msg, std::forward<Args>(params)...);
	}

	template<typename... Args>
	void log_error(const std::string_view str, Args... params) {
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED);
		fmt::print("$> ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_RED);

		std::string msg{str};
		msg.append("\n");

		fmt::print(msg, std::forward<Args>(params)...);
	}

	bool read_file(const std::string_view name, std::vector<char>& out);
};  // namespace io
