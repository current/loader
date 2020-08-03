#pragma once

class syscalls {
	std::unordered_map<std::string, std::pair<uint16_t, uint16_t>> m_indexes;
	std::vector<char> m_stub;

	void* m_call_table;
public:
	syscalls();
	~syscalls();

	void init();
	bool valid(const uintptr_t func, const size_t& size);
	uint16_t get_index(const uintptr_t va, uint16_t& offset);
	size_t func_size(const uint8_t* func);

	template<class T>
	T get(const std::string_view func) {
		return reinterpret_cast<T>(uintptr_t(m_call_table) + (m_indexes[func.data()].first * m_stub.size()));
	};

	uintptr_t operator()(const std::string_view func) {
		return uintptr_t(m_call_table) + (m_indexes[func.data()].first * m_stub.size());
	}

	uintptr_t operator()() {
		return uintptr_t(m_call_table);
	}
};

extern syscalls g_syscalls;