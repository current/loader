#include "../include.h"
#include "../util/io.h"
#include "../util/syscalls.h"
#include "../util/util.h"
#include "process.h"

util::process::process(const SYSTEM_PROCESS_INFORMATION* info) {
	std::wstring name(info->ImageName.Buffer, info->ImageName.Length / sizeof(wchar_t));

	m_name = util::wide_to_multibyte(name);
	m_id = int(info->UniqueProcessId);
}

util::process::~process() {
	m_name.clear();
}

bool util::process::open() {
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
		io::logger->error("failed to open handle to {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return false;
	}

	io::logger->info("opened handle to {}.", m_name);


	return true;
}

bool util::process::read(const uintptr_t addr, void* data, size_t size) {
	static auto nt_read = g_syscalls.get<native::NtReadVirtualMemory>("NtReadVirtualMemory");

	ULONG read;
	auto status = nt_read(m_handle, reinterpret_cast<void*>(addr), data, size, &read);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to read at {:x}, status {:#X}.", addr, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}

bool util::process::write(const uintptr_t addr, void* data, size_t size) {
	static auto nt_write = g_syscalls.get<native::NtWiteVirtualMemory>("NtWriteVirtualMemory");

	ULONG wrote;
	auto status = nt_write(m_handle, reinterpret_cast<void*>(addr), data, size, &wrote);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to write to {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}

bool util::process::free(const uintptr_t addr, size_t size) {
	static auto nt_free = g_syscalls.get<native::NtFreeVirtualMemory>("NtFreeVirtualMemory");

	void* cast_addr = reinterpret_cast<void*>(addr);
	SIZE_T win_size = size;
	auto status = nt_free(m_handle, &cast_addr, &win_size, MEM_RELEASE);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to free at {:x}, status {:#X}.", addr, (status & 0xFFFFFFFF));
		return false;
	}

	return true;
}

bool util::process::thread(const uintptr_t start) {
	static auto nt_create = g_syscalls.get<native::NtCreateThreadEx>("NtCreateThreadEx");
	static auto nt_wait = g_syscalls.get<native::NtWaitForSingleObject>("NtWaitForSingleObject");

	HANDLE out;
	auto status = nt_create(&out, THREAD_ALL_ACCESS, nullptr, m_handle, reinterpret_cast<LPTHREAD_START_ROUTINE>(start), 0, 0x4, 0, 0, 0, 0);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to create thread in {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return false;
	}

	status = nt_wait(out, false, nullptr);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to wait for handle {}, status {:#X}.", out, (status & 0xFFFFFFFF));

		util::close_handle(out);
		return false;
	}

	if (!util::close_handle(out)) {
		return false;
	}

	return true;
}

uintptr_t util::process::load(const std::string_view mod) {
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
		io::logger->error("failed to write name.");
		return {};
	}

	if (!write(name + sizeof(ustr), wpath.data(), wpath.size() * sizeof(wchar_t))) {
		io::logger->error("failed to write path.");
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
		io::logger->error("failed to write shellcode.");
		return {};
	}

	io::logger->info("name : {:x}", name);
	io::logger->info("shellcode : {:x}", code);

	if (!thread(code)) {
		io::logger->error("thread creation failed.");
		return {};
	}

	if (!free(code, shellcode.size())) {
		io::logger->error("failed to free shellcode.");
		return {};
	}

	if (!free(name, 0x1000)) {
		io::logger->error("failed to free name.");
		return {};
	}

	enum_modules();

	return m_modules[mod.data()];
}

uintptr_t util::process::map(const std::string_view mod) {
	auto base = m_modules[mod.data()];
	if (base) {
		return base;
	}

	std::string path{ "C:\\Windows\\SysWOW64\\" };
	path.append(mod.data());

	std::vector<char> buf;
	if (!io::read_file(path, buf)) {
		return {};
	}

	std::vector<char> final_image;

	auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(buf.data());
	auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(buf.data() + dos->e_lfanew);


	final_image.resize(nt->OptionalHeader.SizeOfImage);

	// headers
	std::memcpy(&final_image[0], &buf[0], nt->OptionalHeader.SizeOfHeaders);

	// copy image
	auto secs = IMAGE_FIRST_SECTION(nt);
	for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
		auto sec = secs[i];
		std::memcpy(&final_image[sec.VirtualAddress], &buf[sec.PointerToRawData], sec.SizeOfRawData);
	}

	auto image = allocate(final_image.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!image) {
		io::logger->error("failed to alloc buffer for {}.", path);
		return {};
	}

	io::logger->info("{:x}->{}", image, mod);

	// fix relocations
	

	if (!write(image, final_image.data(), final_image.size())) {
		io::logger->error("failed to write final image.");
		return {};
	}

	m_modules[mod.data()] = image;

	return image;
}

bool util::process::enum_modules() {
	m_modules.clear();

	static auto peb_addr = peb();

	uint32_t ldr;
	if (!read(peb_addr + offsetof(native::peb_t<uint32_t>, Ldr), &ldr, sizeof(ldr))) {
		return false;
	}

	const auto list_head = ldr + offsetof(native::peb_ldr_data_t<uint32_t>, InLoadOrderModuleList);

	uint32_t load_order_flink;
	if (!read(list_head, &load_order_flink, sizeof(load_order_flink))) {
		return false;
	}

	native::ldr_data_table_entry_t<uint32_t> entry;
	for (auto list_curr = load_order_flink; list_curr != list_head;) {
		if (!read(list_curr, &entry, sizeof(entry))) {
			return false;
		}

		list_curr = uint32_t(entry.InLoadOrderLinks.Flink);

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

uintptr_t util::process::peb() {
	static auto nt_proc_info = g_syscalls.get<native::NtQueryInformationProcess>("NtQueryInformationProcess");

	uintptr_t addr;
	auto status = nt_proc_info(m_handle, ProcessWow64Information, &addr, sizeof(addr), nullptr);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to query {} info, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return {};
	}

	return addr;
}

uintptr_t util::process::allocate(size_t size, uint32_t type, uint32_t protection) {
	static auto nt_alloc = g_syscalls.get<native::NtAllocateVirtualMemory>("NtAllocateVirtualMemory");

	void* alloc = nullptr;
	SIZE_T win_size = size;
	auto status = nt_alloc(m_handle, &alloc, 0, &win_size, type, protection);
	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to allocate in {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
		return {};
	}

	return uintptr_t(alloc);
}

uintptr_t util::process::module_export(const uintptr_t base, const std::string_view func) {
	if (!base) {
		io::logger->error("module {} isnt loaded.", m_name);
		return {};
	}

	IMAGE_DOS_HEADER dos{};
	if (!read(base, &dos, sizeof(dos))) {
		io::logger->info("failed to read dos header for {}", m_name);
		return {};
	}

	if (dos.e_magic != IMAGE_DOS_SIGNATURE)
		return {};

	IMAGE_NT_HEADERS32 nt{};
	if (!read(base + dos.e_lfanew, &nt, sizeof(nt))) {
		io::logger->info("failed to read nt header for {}", m_name);
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
		io::logger->info("failed to read export dir for {}", m_name);
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

bool util::process::close() {
	auto ret = util::close_handle(m_handle);
	if (ret) {
		io::logger->info("closed handle to {}.", m_name);
	}
	m_handle = INVALID_HANDLE_VALUE;
	return ret;
}

bool util::fetch_processes(std::vector<process> &out) {
	static auto info = g_syscalls.get<native::NtQuerySystemInformation>("NtQuerySystemInformation");

	std::vector<uint8_t> buf(1);

	ULONG size_needed = 0;
	NTSTATUS status;
	while ((status = info(SystemProcessInformation, buf.data(), buf.size(), &size_needed)) == STATUS_INFO_LENGTH_MISMATCH) {
		buf.resize(size_needed);
	};

	if (!NT_SUCCESS(status)) {
		io::logger->error("failed to get system process info, status {:#X}.", (status & 0xFFFFFFFF));
		return false;
	}

	out.clear();
	auto pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buf.data());
	while (pi->NextEntryOffset) {
		out.emplace_back(util::process(pi));
		pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(uintptr_t(pi) + pi->NextEntryOffset);
	}
	/*std::set_difference(new_list.begin(), new_list.end(), process_list.begin(), process_list.end(), std::inserter(diff, diff.begin()), [&](util::process &l, util::process &r) {
		return l.id() != r.id();
	});

	for (auto& p : diff) {
		io::logger->info("{} is new", p.name());
	}*/

	return true;
}
