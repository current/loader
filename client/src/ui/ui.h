#pragma once

#include "imgui/imgui.h"

#include "imgui/imgui_impl_dx9.h"
#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_stdlib.h"

#include <d3d9.h>

namespace ui {
	extern IDirect3D9* d3d;
	extern IDirect3DDevice9* device;
	extern D3DPRESENT_PARAMETERS present_params;

	LRESULT wnd_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

	HWND create_window(HINSTANCE instance, const std::pair<int, int> size, const std::pair<int, int> pos = { 400, 400 });

	bool create_device(HWND hwnd);
	void cleanup_device();
};