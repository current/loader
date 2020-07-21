#pragma once

class process {
	int m_id;
	std::string m_name;

	HANDLE m_handle = INVALID_HANDLE_VALUE;
public:
	process() = default;
	process(const SYSTEM_PROCESS_INFORMATION* info);
	~process();

	bool open();
	bool read(const uintptr_t addr, void* data, const size_t size);
	bool write(const uintptr_t addr, void* data, const size_t size);

	auto &get_name() { return m_name; }
	auto &get_id() { return m_id; }
};