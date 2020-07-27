#include "../include.h"
#include "../util/io.h"
#include "../util/util.h"
#include "process.h"

uintptr_t util::process32::module_export(const uintptr_t base, const std::string_view func) {
	if (!base) {
		io::log_error("module {} isnt loaded.", m_name);
		return {};
	}

	IMAGE_DOS_HEADER dos{};
	if (!read(base, &dos, sizeof(dos))) {
		io::log_error("failed to read dos header for {}", m_name);
		return {};
	}

	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		return {};

	native::nt_headers_t<false> nt{};
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

				return module_export(load(fwd_mod_name), fwd_func_name);
			}

			return proc_addr;
		}
	}

	return {};
}

uintptr_t util::process32::load(const std::string_view mod) {
	auto base = m_modules[mod.data()];
	if (base) {
		return base;
	}

	static auto loaddll = module_export(m_modules["ntdll.dll"], "LdrLoadDll");

	auto name = allocate(0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	std::string path{ "C:\\Windows\\SysWOW64\\" };
	path.append(mod.data());

	native::unicode_string_t<uint32_t> ustr = { 0 };

	auto wpath = util::multibyte_to_wide(path.data());
	ustr.Buffer = name + sizeof(ustr);
	ustr.MaximumLength = ustr.Length = wpath.size() * sizeof(wchar_t);

	if (!write(name, &ustr, sizeof(ustr))) {
		io::log_error("failed to write name.");
		return {};
	}

	if (!write(name + sizeof(ustr), wpath.data(), wpath.size() * sizeof(wchar_t))) {
		io::log_error("failed to write path.");
		return {};
	}

	static std::vector<uint8_t> shellcode = { 0x55, 0x89, 0xE5, 0x68, 0xEF, 0xBE, 0xAD,
		0xDE, 0x68, 0xEF, 0xBE, 0xAD, 0xDE, 0x6A, 0x00, 0x6A, 0x00, 0xB8,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x89, 0xEC, 0x5D, 0xC3 };
	*reinterpret_cast<uint32_t*>(&shellcode[4]) = name + 0x800;
	*reinterpret_cast<uint32_t*>(&shellcode[9]) = name;
	*reinterpret_cast<uint32_t*>(&shellcode[18]) = loaddll;

	auto code = allocate(shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!write(code, shellcode.data(), shellcode.size())) {
		io::log_error("failed to write shellcode.");
		return {};
	}

	io::log("name : {:x}", name);
	io::log("shellcode : {:x}", code);

	if (!thread(code)) {
		io::log_error("thread creation failed.");
		return {};
	}

	if (!free(code, shellcode.size())) {
		io::log_error("failed to free shellcode.");
		return {};
	}

	if (!free(name, 0x1000)) {
		io::log_error("failed to free name.");
		return {};
	}

	enum_modules();

	return m_modules[mod.data()];
}

bool util::fetch_system_data(system_data_t& out) {
	static auto info = g_syscalls.get<native::NtQuerySystemInformation>("NtQuerySystemInformation");

	std::vector<uint8_t> buf(1);

	ULONG size_needed = 0;
	NTSTATUS status;
	while ((status = info(native::SystemProcessInformation, buf.data(), buf.size(), &size_needed)) == STATUS_INFO_LENGTH_MISMATCH) {
		buf.resize(size_needed);
	};

	if (!NT_SUCCESS(status)) {
		io::log_error("failed to get system process info, status {:#X}.", (status & 0xFFFFFFFF));
		return false;
	}

	std::vector<thread_data_t> threads;
	std::vector<process_data_t> processes;
	auto pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buf.data());

	while (pi->NextEntryOffset) {
		std::wstring name(pi->ImageName.Buffer, pi->ImageName.Length / sizeof(wchar_t));
		processes.emplace_back(process_data_t{ util::wide_to_multibyte(name), int(pi->UniqueProcessId) });

		auto ti = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(uintptr_t(pi) + sizeof(SYSTEM_PROCESS_INFORMATION));

		for (auto i = 0; i < pi->NumberOfThreads; ++i) {
			auto dat = ti[i];
			threads.emplace_back(thread_data_t{int(dat.ClientId.UniqueProcess), uintptr_t(dat.ClientId.UniqueThread), dat.ThreadState});
		}

		pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(uintptr_t(pi) + pi->NextEntryOffset);
	}


	out.processes = std::move(processes);
	out.threads = std::move(threads);

	return true;
}

bool util::fetch_process_handles(const int pid, std::vector<handle_info_t>& out) {
	static auto info = g_syscalls.get<native::NtQuerySystemInformation>("NtQuerySystemInformation");

	std::vector<uint8_t> buf(1);

	ULONG size_needed = 0;
	NTSTATUS status;
	while ((status = info(native::SystemHandleInformation, buf.data(), buf.size(), &size_needed)) == STATUS_INFO_LENGTH_MISMATCH) {
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
