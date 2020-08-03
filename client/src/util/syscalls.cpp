#include "../include.h"
#include "io.h"
#include "util.h"
#include "syscalls.h"

syscalls g_syscalls;

syscalls::syscalls() {
	m_call_table = VirtualAlloc(0, 0x100000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	std::memset(m_call_table, 0x90, 0x100000);
}

syscalls::~syscalls() {
	VirtualFree(m_call_table, 0, MEM_RELEASE);
}

void syscalls::init() {
	io::log("syscalls call table : {:x}", uintptr_t(m_call_table));

	static auto nt = pe::ntdll();
	for (auto& exp : nt.exports()) {
		auto addr = exp.second;

		uint16_t offset;
		auto idx = get_index(addr, offset);

		if (!idx) continue;

		m_indexes[exp.first] = std::make_pair(idx, offset);

		if (m_stub.empty()) {
			auto s = func_size(reinterpret_cast<uint8_t*>(addr));

			m_stub.resize(s);

			std::memcpy(&m_stub[0], reinterpret_cast<void*>(addr), s);
		}
	}

	for (auto& [name, pair] : m_indexes) {
		auto& [idx, offset] = pair;

		auto addr = uintptr_t(m_call_table) + (idx * m_stub.size());
		std::memcpy(reinterpret_cast<void*>(addr), m_stub.data(), m_stub.size());

		*reinterpret_cast<uint8_t*>(addr + m_stub.size() - 1) = 0xc3;
		*reinterpret_cast<uint16_t*>(addr + offset + 1) = idx;
	}
}

bool syscalls::valid(const uintptr_t addr, const size_t& size) {
	auto func = reinterpret_cast<uint8_t*>(addr);

	// mov r10, rcx
	uint32_t a = func[0] + func[1] + func[2];
	if (a != 0x1a8) {
		return false;
	}

	for (size_t i{}; i < size; i++) {
		auto op = func[i];
		auto next = func[i + 1];

		if (op == 0x0f && next == 0x05) {
			return true;
		}
	}

	return false;
}

uint16_t syscalls::get_index(const uintptr_t va, uint16_t& offset) {
	auto func = reinterpret_cast<uint8_t*>(va);
	auto size = func_size(reinterpret_cast<uint8_t*>(va));
	if (!valid(va, size)) {
		return 0;
	}

	for (size_t i{}; i < size; i++) {
		auto op = func[i];
		if (op == 0xb8) {
			offset = i;

			return *reinterpret_cast<uint16_t*>(va + i + 1);
		}
	}
	return 0;
}

size_t syscalls::func_size(const uint8_t* func) {
	for (size_t i = 0; i < 64; i++) {
		auto op = func[i];
		if (op == 0xc3 || op == 0xc2) {
			return i + 1;
		}
	}
	return 0;
}
