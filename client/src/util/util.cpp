#include "../include.h"
#include "util.h"
#include "io.h"
#include "syscalls.h"

std::string util::wide_to_multibyte(const std::wstring& str) {
	std::string ret;
	size_t str_len;

	// check if not empty str
	if (str.empty())
		return{};

	// count size
	str_len = WideCharToMultiByte(CP_UTF8, 0, &str[0], str.size(), 0, 0, 0, 0);

	// setup return value
	ret = std::string(str_len, 0);

	// final conversion
	WideCharToMultiByte(CP_UTF8, 0, &str[0], str.size(), &ret[0], str_len, 0, 0);

	return ret;
}

std::wstring util::multibyte_to_wide(const std::string& str) {
	size_t      size;
	std::wstring out;

	// get size
	size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.size() + 1, 0, 0);

	out.resize(size);

	// finally convert
	MultiByteToWideChar(CP_UTF8, 0, str.c_str(), str.size() + 1, &out[0], size);

	return out;
}

bool util::close_handle(HANDLE handle) {
	if (!handle) {
		io::log_error("invalid handle specified to close.");
		return false;
	}

	static auto nt_close = g_syscalls.get<native::NtClose>("NtClose");

	auto status = nt_close(handle);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to close {}, status {:#X}.", handle, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}
