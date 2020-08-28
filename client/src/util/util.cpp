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
	ret.resize(str_len);

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
	static auto nt_close = g_syscalls.get<native::NtClose>("NtClose");

	auto status = nt_close(handle);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to close {}, status {:#X}.", handle, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}


bool pe::get_all_modules(std::unordered_map<std::string, virtual_image>& modules) {
	modules.clear();

	auto peb = util::peb();
	if (!peb) return false;

	if (!peb->Ldr->InMemoryOrderModuleList.Flink) return false;

	auto* list = &peb->Ldr->InMemoryOrderModuleList;

	for (auto i = list->Flink; i != list; i = i->Flink) {
		auto entry = CONTAINING_RECORD(i, native::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (!entry)
			continue;

		auto name = util::wide_to_multibyte(entry->BaseDllName.Buffer);
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);

		modules[name] = virtual_image(entry->DllBase);
	}

	return !modules.empty();
}