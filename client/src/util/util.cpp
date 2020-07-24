#include "../include.h"
#include "util.h"
#include "io.h"
#include "syscalls.h"

std::unordered_map<std::string, pe::virtual_image> util::loaded_modules;

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


native::_PEB* util::cur_peb() {
	return reinterpret_cast<native::_PEB*>(__readgsqword(0x60));
}

bool util::init() {
	auto peb = cur_peb();
	if (!peb) return false;

	if (!peb->Ldr->InMemoryOrderModuleList.Flink) return false;

	auto* list = &peb->Ldr->InMemoryOrderModuleList;

	for (auto i = list->Flink; i != list; i = i->Flink) {
		auto entry = CONTAINING_RECORD(i, native::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (!entry)
			continue;

		auto name = wide_to_multibyte(entry->BaseDllName.Buffer);
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);

		loaded_modules[name] = pe::virtual_image(entry->DllBase);
	}

	return true;
}

bool util::close_handle(HANDLE handle) {
	if (!handle) {
		io::logger->error("invalid handle specified to close.");
		return false;
	}

	static auto nt_close = g_syscalls.get<native::NtClose>("NtClose");

	auto status = nt_close(handle);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to close {}, status {:#X}.", handle, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}
