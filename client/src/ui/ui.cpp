#include "../include.h"
#include "ui.h"

ID3D11Device* ui::device;
ID3D11DeviceContext* ui::device_context;
IDXGISwapChain* ui::swap_chain;
ID3D11RenderTargetView* ui::main_render_target;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI ui::wnd_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
	if (ImGui_ImplWin32_WndProcHandler(hwnd, message, wparam, lparam))
		return true;

	switch (message)
	{
	case WM_SIZE:
		if (wparam != SIZE_MINIMIZED) {
			cleanup_target();
			swap_chain->ResizeBuffers(0, (UINT)LOWORD(lparam), (UINT)HIWORD(wparam), DXGI_FORMAT_UNKNOWN, 0);
			create_target();
		}
		return 0;
	case WM_SYSCOMMAND:
		if ((wparam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
			return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}

	return DefWindowProc(hwnd, message, wparam, lparam);
}

HWND ui::create(HINSTANCE instance, const std::pair<int, int> size, const std::pair<int, int> pos /*= { 400, 400 }*/) {
	WNDCLASSEX wc;

	std::memset(&wc, 0, sizeof(wc));
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = CS_CLASSDC;
	wc.lpfnWndProc = wnd_proc;
	wc.hInstance = instance;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = 0;
	wc.lpszClassName = "LoaderClass";

	RegisterClassEx(&wc);

	auto flag = WS_OVERLAPPEDWINDOW;
	flag &= ~WS_MAXIMIZEBOX;
	flag &= ~WS_SIZEBOX;
	return CreateWindowEx(WS_EX_TOPMOST, wc.lpszClassName, "client", flag, pos.first, pos.second, size.first, size.second, 0, 0, wc.hInstance, 0);
}

bool ui::create_device(HWND hwnd) {
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = hwnd;
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	//createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	auto ret = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2,
		D3D11_SDK_VERSION, &sd, &swap_chain, &device, &featureLevel, &device_context);
	if (ret != S_OK)
		return false;

	create_target();

	return true;
}

void ui::create_target() {
	ID3D11Texture2D* pBackBuffer;
	swap_chain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
	device->CreateRenderTargetView(pBackBuffer, NULL, &main_render_target);
	pBackBuffer->Release();
}

void ui::cleanup_target() {
	if (main_render_target) {
		main_render_target->Release();
		main_render_target = nullptr;
	}
}

void ui::cleanup_device() {
	cleanup_target();
	if (swap_chain) {
		swap_chain->Release();
	}

	if (device_context) {
		device_context->Release();
	}

	if (device) {
		device->Release();
	}
}