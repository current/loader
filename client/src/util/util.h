#pragma once

#include "native.h"
#include "pe.h"

namespace util {

extern std::unordered_map<std::string, pe::image> loaded_modules;

std::string wide_to_multibyte(const std::wstring &str);

native::_PEB *get_peb();

bool init();

static pe::image& ntdll() {
	static pe::image nt{};
	if (!nt) {
		nt = loaded_modules["ntdll.dll"];
		nt.parse_exports();
	}
	return nt;
}

};  // namespace util

