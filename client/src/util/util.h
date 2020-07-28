#pragma once

#include "native.h"

namespace util {
	std::string wide_to_multibyte(const std::wstring& str);
	std::wstring multibyte_to_wide(const std::string& str);

	__forceinline native::_PEB* peb() {
		return reinterpret_cast<native::_PEB*>(__readgsqword(0x60));
	}

	bool close_handle(HANDLE handle);

};  // namespace util

#include "../injection/pe.h"