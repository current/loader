#pragma once

#include "imgui/imgui.h"

#include "imgui/imgui_impl_win32.h"
#include "imgui/imgui_impl_dx11.h"
#include "imgui/imgui_stdlib.h"
#include <d3d11.h>

namespace ui {
	extern ID3D11Device* device;
	extern ID3D11DeviceContext* device_context;
	extern IDXGISwapChain* swap_chain;
	extern ID3D11RenderTargetView* main_render_target;

	LRESULT wnd_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam);

	HWND create(HINSTANCE instance, const std::pair<int, int> size, const std::pair<int, int> pos = { 400, 400 });

	bool create_device(HWND hwnd);
	void create_target();
	void cleanup_target();
	void cleanup_device();
};