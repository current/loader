#pragma once
#include "../ui/ui.h"

namespace hwid {
	struct hwid_data_t {
		std::string gpu;

		uint64_t uid;
	};

	__forceinline bool fetch(hwid_data_t& out) {
		IDXGIDevice* dxgi_device;
		if (ui::device->QueryInterface(&dxgi_device) != S_OK) {
			return false;
		}

		IDXGIAdapter* adapter;
		if (dxgi_device->GetParent(__uuidof(IDXGIAdapter), reinterpret_cast<void**>(&adapter)) != S_OK) {
			return false;
		}

		DXGI_ADAPTER_DESC desc;
		if (adapter->GetDesc(&desc) != S_OK) {
			return false;
		}

		out.uid += desc.VendorId >> 1;
		out.uid += desc.DeviceId >> 1;
		out.uid += desc.DedicatedVideoMemory << 5;

		out.gpu = util::wide_to_multibyte(desc.Description);

		adapter->Release();
		dxgi_device->Release();

		return true;
	}
};