#pragma once

namespace util {
	class base_process {
	protected:
		HANDLE m_handle;
		int m_id;
		std::string m_name;
	public:
		base_process() : m_handle{ INVALID_HANDLE_VALUE }, m_name{}, m_id{} {}
		~base_process() = default;

		bool open();
		bool read(const uintptr_t addr, void* data, size_t size);
		bool write(const uintptr_t addr, void* data, size_t size);
		bool free(const uintptr_t addr, size_t size, uint32_t type = MEM_RELEASE);
		bool info(native::PROCESSINFOCLASS proc_info, void* data, size_t size);
		bool thread(const uintptr_t func);
		bool close();

		uintptr_t allocate(size_t size, uint32_t type, uint32_t protection);

		auto& handle() { return m_handle; }
		auto& name() { return m_name; }
		auto& id() { return m_id; }
	};

	struct thread_data_t {
		HANDLE handle;
		uint32_t state;
	};

	struct process_data_t {
		int id;
		std::string name;
		std::vector<thread_data_t> threads;
	};

	template<typename T>
	class process : public base_process {
		std::unordered_map<std::string, uintptr_t> m_modules;
	public:
		process(const process_data_t& data) {
			m_name = data.name;
			m_id = data.id;
		}
		~process() = default;

		bool enum_modules();

		uintptr_t peb();
		uintptr_t module_export(const uintptr_t base, const std::string_view func);
		uintptr_t map(const std::string_view module_name);
	};

	struct handle_info_t {
		uint32_t access;
		uintptr_t handle;
		uint32_t obj_type;
	};

	bool fetch_processes(std::vector<process_data_t>& out, bool threads = false);
	bool fetch_process_handles(const int pid, std::vector<handle_info_t>& out);
};
