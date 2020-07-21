#include "../include.h"
#include "io.h"
#include "util.h"

std::unordered_map<std::string, pe::image> util::loaded_modules;

std::string util::wide_to_multibyte(const std::wstring& str) {
	std::string ret;
	int32_t str_len;

	// check if not empty str
	if (str.empty())
		return{};

	// count size
	str_len = WideCharToMultiByte(CP_UTF8, 0, &str[0], (int32_t)str.size(), 0, 0, 0, 0);

	// setup return value
	ret = std::string(str_len, 0);

	// final conversion
	WideCharToMultiByte(CP_UTF8, 0, &str[0], (int32_t)str.size(), &ret[0], str_len, 0, 0);

	return ret;
}


native::_PEB* util::get_peb() {
	return reinterpret_cast<native::_PEB*>(__readgsqword(0x60));
}

bool util::init() {
	auto peb = get_peb();
	if (!peb) return false;

	if (!peb->Ldr->InMemoryOrderModuleList.Flink) return false;

	auto* list = &peb->Ldr->InMemoryOrderModuleList;

	for (auto i = list->Flink; i != list; i = i->Flink) {
		auto entry = CONTAINING_RECORD(i, native::LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if (!entry)
			continue;

		auto name = wide_to_multibyte(entry->BaseDllName.Buffer);
		std::transform(name.begin(), name.end(), name.begin(), ::tolower);

		loaded_modules[name] = pe::image(entry->DllBase);
	}

	return true;
}
