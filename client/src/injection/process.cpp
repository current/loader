#include "../include.h"
#include "../util/io.h"
#include "../util/syscalls.h"
#include "../util/util.h"
#include "process.h"

process::process(const SYSTEM_PROCESS_INFORMATION* info) {
	std::wstring name;
	name.resize(info->ImageName.Length);

	std::memcpy(&name[0], &info->ImageName.Buffer[0], name.size());

	m_name = util::wide_to_multibyte(name);
	m_id = int(info->UniqueProcessId);
}

process::~process() {
	m_name.clear();
}

bool process::open() {
	CLIENT_ID cid = { HANDLE(m_id), 0 };
	OBJECT_ATTRIBUTES oa;
	oa.Length = sizeof(oa);
	oa.Attributes = 0;
	oa.RootDirectory = 0;
	oa.SecurityDescriptor = 0;
	oa.ObjectName = 0;
	oa.SecurityQualityOfService = 0;

	static auto nt_open = g_syscalls.get<native::NtOpenProcess>("NtOpenProcess");

	if (!NT_SUCCESS(nt_open(&m_handle, PROCESS_ALL_ACCESS, &oa, &cid))) {
		io::logger->error("failed to open handle to {}.", m_name);
		return false;
	}

	return true;
}

bool process::read(const uintptr_t addr, void* data, const size_t size) {
	static auto nt_read = g_syscalls.get<native::NtReadVirtualMemory>("NtReadVirtualMemory");
	if (!m_handle) {
		io::logger->error("invalid process handle.", m_name);
		return false;
	}

	ULONG read;
	if (!NT_SUCCESS(nt_read(m_handle, reinterpret_cast<void*>(addr), data, size, &read))) {
		io::logger->error("failed to read to {}.", m_name);
		return false;
	}

	return true;
}

bool process::write(const uintptr_t addr, void* data, const size_t size) {
	static auto nt_write = g_syscalls.get<native::NtWiteVirtualMemory>("NtWiteVirtualMemory");
	if (!m_handle) {
		io::logger->error("invalid process handle.", m_name);
		return false;
	}

	ULONG wrote;
	if (!NT_SUCCESS(nt_write(m_handle, reinterpret_cast<void*>(addr), data, size, &wrote))) {
		io::logger->error("failed to write to {}.", m_name);
		return false;
	}

	return true;
}
