#include "../include.h"
#include "../util/io.h"
#include "../util/util.h"
#include "../util/apiset.h"
#include "../util/syscalls.h"
#include "process.h"

bool util::base_process::open() {
	CLIENT_ID cid = { HANDLE(m_id), 0 };
	OBJECT_ATTRIBUTES oa;
	oa.Length = sizeof(oa);
	oa.Attributes = 0;
	oa.RootDirectory = 0;
	oa.SecurityDescriptor = 0;
	oa.ObjectName = 0;
	oa.SecurityQualityOfService = 0;

	static auto nt_open = g_syscalls.get<native::NtOpenProcess>("NtOpenProcess");

	auto status = nt_open(&m_handle, PROCESS_ALL_ACCESS, &oa, &cid);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to open handle to {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return false;
	}

	io::log("opened handle to {}.", m_name);

	return true;
}

bool util::base_process::read(const uintptr_t addr, void* data, size_t size) {
	static auto nt_read = g_syscalls.get<native::NtReadVirtualMemory>("NtReadVirtualMemory");

	ULONG read;
	auto status = nt_read(m_handle, reinterpret_cast<void*>(addr), data, size, &read);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to read at {:x}, status {:#X}.", addr, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}

bool util::base_process::write(const uintptr_t addr, void* data, size_t size) {
	static auto nt_write = g_syscalls.get<native::NtWriteVirtualMemory>("NtWriteVirtualMemory");

	ULONG wrote;
	auto status = nt_write(m_handle, reinterpret_cast<void*>(addr), data, size, &wrote);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to write to {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}

bool util::base_process::free(const uintptr_t addr, size_t size, uint32_t type /*= MEM_RELEASE*/) {
	static auto nt_free = g_syscalls.get<native::NtFreeVirtualMemory>("NtFreeVirtualMemory");

	SIZE_T win_size = size;
	void* addr_cast = reinterpret_cast<void*>(addr);
	auto status = nt_free(m_handle, &addr_cast, &win_size, MEM_RELEASE);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to free at {:x}, status {:#X}.", addr, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}

bool util::base_process::info(native::PROCESSINFOCLASS proc_info, void* data, size_t size) {
	static auto nt_proc_info = g_syscalls.get<native::NtQueryInformationProcess>("NtQueryInformationProcess");
	auto status = nt_proc_info(m_handle, proc_info, data, size, nullptr);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to query {} info, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}

bool util::base_process::thread(const uintptr_t func) {
	static auto nt_create = g_syscalls.get<native::NtCreateThreadEx>("NtCreateThreadEx");
	static auto nt_wait = g_syscalls.get<native::NtWaitForSingleObject>("NtWaitForSingleObject");

	HANDLE out;
	auto status = nt_create(&out, THREAD_ALL_ACCESS, nullptr, m_handle, reinterpret_cast<LPTHREAD_START_ROUTINE>(func), 0, 0x4, 0, 0, 0, 0);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to create thread in {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return false;
	}

	status = nt_wait(out, false, nullptr);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to wait for handle {}, status {:#X}.", out, (status & 0xFFFFFFFF));

		util::close_handle(out);
		return false;
	}

	if (!util::close_handle(out)) {
		return false;
	}

	return true;
}

bool util::base_process::close() {
	auto ret = util::close_handle(m_handle);
	if (ret) {
		io::log("closed handle to {}.", m_name);
	}
	m_handle = INVALID_HANDLE_VALUE;
	return ret;
}

uintptr_t util::base_process::allocate(size_t size, uint32_t type, uint32_t protection) {
	static auto nt_alloc = g_syscalls.get<native::NtAllocateVirtualMemory>("NtAllocateVirtualMemory");

	void* alloc = nullptr;
	SIZE_T win_size = size;
	auto status = nt_alloc(m_handle, &alloc, 0, &win_size, type, protection);
	if (!NT_SUCCESS(status)) {
		io::log_error("failed to allocate in {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return {};
	}

	return uintptr_t(alloc);
}

template<typename T>
bool util::process<T>::enum_modules() {
	m_modules.clear();

	static auto peb_addr = peb();

	T ldr;
	if (!read(peb_addr + offsetof(native::peb_t<T>, Ldr), &ldr, sizeof(ldr))) {
		return false;
	}

	const auto list_head = ldr + offsetof(native::peb_ldr_data_t<T>, InLoadOrderModuleList);

	T load_order_flink;
	if (!read(list_head, &load_order_flink, sizeof(load_order_flink))) {
		return false;
	}

	native::ldr_data_table_entry_t<T> entry;
	for (auto list_curr = load_order_flink; list_curr != list_head;) {
		if (!read(list_curr, &entry, sizeof(entry))) {
			return false;
		}

		list_curr = entry.InLoadOrderLinks.Flink;

		std::vector<wchar_t> name_vec(entry.FullDllName.Length);

		if (!read(entry.FullDllName.Buffer, &name_vec[0], name_vec.size())) {
			continue;
		}

		auto name = util::wide_to_multibyte(name_vec.data());
		auto pos = name.rfind('\\');
		if (pos != std::string::npos) {
			name = name.substr(pos + 1);
			std::transform(name.begin(), name.end(), name.begin(), ::tolower);

			m_modules[name] = entry.DllBase;
		}
	}

	return true;
}

template<typename T>
uintptr_t util::process<T>::peb() {
	constexpr bool is64 = std::is_same_v<T, uint64_t>;
	if (is64) {
		native::PROCESS_EXTENDED_BASIC_INFORMATION proc_info;
		proc_info.Size = sizeof(proc_info);
		if (!info(native::ProcessBasicInformation, &proc_info, sizeof(proc_info))) {
			return {};
		}

		return uintptr_t(proc_info.BasicInfo.PebBaseAddress);
	}

	uintptr_t addr;
	if (!info(native::ProcessWow64Information, &addr, sizeof(addr))) {
		return {};
	}

	return addr;
}

template<typename T>
uintptr_t util::process<T>::module_export(const uintptr_t base, const std::string_view func) {
	if (!base) {
		return {};
	}

	IMAGE_DOS_HEADER dos{};
	if (!read(base, &dos, sizeof(dos))) {
		io::log_error("failed to read dos header for {}", m_name);
		return {};
	}

	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		return {};

	constexpr bool is64 = std::is_same_v<T, uint64_t>;
	pe::nt_headers_t<is64> nt{};
	if (!read(base + dos.e_lfanew, &nt, sizeof(nt))) {
		io::log_error("failed to read nt header for {}", m_name);
		return {};
	}

	if (nt.Signature != IMAGE_NT_SIGNATURE)
		return {};

	IMAGE_EXPORT_DIRECTORY exp_dir{};
	auto exp_va = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
		.VirtualAddress;
	auto exp_dir_size =
		nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	auto exp_dir_start = base + exp_va;
	auto exp_dir_end = exp_dir_start + exp_dir_size;

	if (!read(exp_dir_start, &exp_dir, sizeof(exp_dir))) {
		io::log_error("failed to read export dir for {}", m_name);
		return {};
	}

	auto funcs = base + exp_dir.AddressOfFunctions;
	auto ords = base + exp_dir.AddressOfNameOrdinals;
	auto names = base + exp_dir.AddressOfNames;

	for (int i = 0; i < exp_dir.NumberOfFunctions; ++i) {
		uint32_t name_rva{};
		uint32_t func_rva{};
		uint16_t ordinal{};

		if (!read(names + (i * sizeof(uint32_t)), &name_rva, sizeof(uint32_t))) {
			continue;
		}
		std::string name;
		name.resize(func.size());

		if (!read(base + name_rva, &name[0], name.size())) {
			continue;
		}

		if (name == func) {
			if (!read(ords + (i * sizeof(uint16_t)), &ordinal, sizeof(uint16_t))) {
				return {};
			}

			if (!read(funcs + (ordinal * sizeof(uint32_t)), &func_rva, sizeof(uint32_t))) {
				return {};
			}

			auto proc_addr = base + func_rva;
			if (proc_addr >= exp_dir_start && proc_addr < exp_dir_end) {
				std::array<char, 255> forwarded_name;
				read(proc_addr, &forwarded_name[0], forwarded_name.size());

				std::string name_str(forwarded_name.data());

				size_t delim = name_str.find('.');
				if (delim == std::string::npos) return {};

				std::string fwd_mod_name = name_str.substr(0, delim + 1);
				fwd_mod_name += "dll";

				std::transform(fwd_mod_name.begin(), fwd_mod_name.end(), fwd_mod_name.begin(), ::tolower);

				std::string fwd_func_name = name_str.substr(delim + 1);

				return module_export(map(fwd_mod_name), fwd_func_name);
			}

			return proc_addr;
		}
	}

	return {};
}

template<typename T>
uintptr_t util::process<T>::map(const std::string_view module_name) {
	std::string mod{ module_name };
	if (g_apiset.find(mod)) {
		io::log("resolved {} -> {}", module_name, mod);
	}

	auto base = m_modules[mod];
	if (base) {
		return base;
	}

	io::log("mapping {}", module_name);

	constexpr bool is64 = std::is_same_v<T, uint64_t>;
	std::string path{ is64 ? "C:\\Windows\\System32\\" : "C:\\Windows\\SysWOW64\\" };
	path.append(mod);

	std::vector<char> local_image;
	if (!io::read_file(path, local_image)) {
		return {};
	}

	pe::image<is64> img(local_image);

	if (!img) {
		io::log_error("failed to init image.");
		return {};
	}

	std::vector<char> remote_image;
	img.copy(remote_image);

	base = allocate(remote_image.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!base) {
		return {};
	}

	img.relocate(remote_image, base);

	for (auto& [mod, funcs] : img.imports()) {
		for (auto& func : funcs) {
			auto addr = module_export(map(mod), func.name);

			io::log("[mapper] {}->{}->{:x}", mod, func.name, addr);

			*reinterpret_cast<T*>(&remote_image[func.rva]) = addr;
		}
	}

	if (!write(base, remote_image.data(), remote_image.size())) {
		free(base, remote_image.size());

		return {};
	}

	io::log("{}->{:x}", mod, base);

	m_modules[mod] = base;

	return base;
}

// explicit template instantiation
template class util::process<uint64_t>;
template class util::process<uint32_t>;

bool util::fetch_processes(std::vector<process_data_t>& out, bool threads /*= false*/) {
	static auto info = g_syscalls.get<native::NtQuerySystemInformation>("NtQuerySystemInformation");

	out.clear();
	std::vector<uint8_t> buf(1);

	ULONG size_needed = 0;
	NTSTATUS status;
	while ((status = info(SystemProcessInformation, buf.data(), buf.size(), &size_needed)) == STATUS_INFO_LENGTH_MISMATCH) {
		buf.resize(size_needed);
	};

	if (!NT_SUCCESS(status)) {
		io::log_error("failed to get system process info, status {:#X}.", (status & 0xFFFFFFFF));
		return false;
	}

	auto pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buf.data());

	while (pi->NextEntryOffset) {
		std::wstring name(pi->ImageName.Buffer, pi->ImageName.Length / sizeof(wchar_t));
		process_data_t data{int(pi->UniqueProcessId), util::wide_to_multibyte(name)};
		
		if (!threads) {
			out.emplace_back(data);
			
			pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(uintptr_t(pi) + pi->NextEntryOffset);
			continue;
		}

		std::vector<thread_data_t> threads;
		auto ti = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(uintptr_t(pi) + sizeof(SYSTEM_PROCESS_INFORMATION));
		for (auto i = 0; i < pi->NumberOfThreads; ++i) {
			auto thread = ti[i];
			threads.emplace_back(thread_data_t{ thread.ClientId.UniqueThread, thread.ThreadState });
		}

		pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(uintptr_t(pi) + pi->NextEntryOffset);
	}

	return true;
}

bool util::fetch_process_handles(const int pid, std::vector<handle_info_t>& out) {
	static auto info = g_syscalls.get<native::NtQuerySystemInformation>("NtQuerySystemInformation");

	std::vector<uint8_t> buf(1);

	ULONG size_needed = 0;
	NTSTATUS status;
	/* SystemHandleInformation */
	while ((status = info(static_cast<SYSTEM_INFORMATION_CLASS>(16), buf.data(), buf.size(), &size_needed)) == STATUS_INFO_LENGTH_MISMATCH) {
		buf.resize(size_needed);
	};

	if (!NT_SUCCESS(status)) {
		io::log_error("failed to get system handle info, status {:#X}.", (status & 0xFFFFFFFF));
		return false;
	}

	auto hi = reinterpret_cast<native::SYSTEM_HANDLE_INFORMATION*>(buf.data());
	for (ULONG i = 0; i < hi->NumberOfHandles; i++) {
		auto handle = &hi->Handles[i];
		if (handle->UniqueProcessId == pid) {
			out.emplace_back(handle_info_t{ handle->GrantedAccess, uintptr_t(handle->HandleValue), handle->ObjectTypeIndex });
		}
	}
}
