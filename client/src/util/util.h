#pragma once

#include "native.h"
#include "../injection/pe.h"

namespace util {

	extern std::unordered_map<std::string, pe::virtual_image> loaded_modules;

	std::string wide_to_multibyte(const std::wstring& str);
	std::wstring multibyte_to_wide(const std::string& str);

	native::_PEB* cur_peb();

	bool init();

	static pe::virtual_image& ntdll() {
		static pe::virtual_image nt{};
		if (!nt) {
			nt = loaded_modules["ntdll.dll"];
			nt.parse_exports();
		}
		return nt;
	}

	bool close_handle(HANDLE handle);

};  // namespace util