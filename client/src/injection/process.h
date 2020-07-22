#pragma once

namespace util {
	class process {
		int m_id;
		std::string m_name;
		std::unordered_map<std::string, uintptr_t> m_modules;

		HANDLE m_handle;
	public:
		process() : m_handle{ INVALID_HANDLE_VALUE } {};
		process(const SYSTEM_PROCESS_INFORMATION* info);
		~process();

		bool open();
		bool read(const uintptr_t addr, void* data, size_t size);
		bool write(const uintptr_t addr, void* data, size_t size);
		bool free(const uintptr_t addr, size_t size);
		bool thread(const uintptr_t start);
		bool enum_modules();

		uintptr_t peb();
		uintptr_t load(const std::string_view mod);
		uintptr_t allocate(size_t size, uint32_t type, uint32_t protection);
		uintptr_t module_export(const std::string_view name, const std::string_view func);

		bool close();

		operator bool() const { return m_handle != INVALID_HANDLE_VALUE; }

		auto& name() { return m_name; }
		auto& id() { return m_id; }
		auto& handle() { return m_handle; }
	};

	extern std::vector<process> process_list;

	bool fetch_processes();
};
