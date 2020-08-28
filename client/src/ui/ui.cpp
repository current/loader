#include "../include.h"
#include "ui.h"

IDirect3D9* ui::d3d;
IDirect3DDevice9* ui::device;
D3DPRESENT_PARAMETERS ui::present_params;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT ui::wnd_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
	if (ImGui_ImplWin32_WndProcHandler(hwnd, message, wparam, lparam))
		return true;

	switch (message) {
		case WM_DESTROY:
			PostQuitMessage(0);
			return 0;
	}

	return DefWindowProc(hwnd, message, wparam, lparam);
}

HWND ui::create_window(HINSTANCE instance, const std::pair<int, int> size, const std::pair<int, int> pos /*= { 400, 400 }*/) {
	WNDCLASSEX wc;

	std::memset(&wc, 0, sizeof(wc));
	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = CS_CLASSDC;
	wc.lpfnWndProc = wnd_proc;
	wc.hInstance = instance;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = 0;
	wc.lpszClassName = L"LoaderClass";

	RegisterClassEx(&wc);

	auto flag = WS_POPUP;
	/*flag &= ~WS_MAXIMIZEBOX;
	flag &= ~WS_SIZEBOX;*/
	return CreateWindowEx(WS_EX_TOPMOST, wc.lpszClassName, L"client", flag, pos.first, pos.second, size.first, size.second, 0, 0, wc.hInstance, 0);
}

bool ui::create_device(HWND hwnd) {
	d3d = Direct3DCreate9(D3D_SDK_VERSION);
	if (!d3d) {
		return false;
	}

	std::memset(&present_params, 0, sizeof(present_params));

	present_params.Windowed = TRUE;
	present_params.SwapEffect = D3DSWAPEFFECT_DISCARD;
	present_params.BackBufferFormat = D3DFMT_UNKNOWN;
	present_params.EnableAutoDepthStencil = TRUE;
	present_params.AutoDepthStencilFormat = D3DFMT_D16;
	present_params.PresentationInterval = D3DPRESENT_INTERVAL_ONE;

	auto res = d3d->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hwnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &present_params, &device);
	if (res != D3D_OK) {
		return false;
	}

	return true;
}

void ui::cleanup_device() {
	device->Release();
	d3d->Release();
}