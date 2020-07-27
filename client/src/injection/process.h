#pragma once
#include "../util/syscalls.h"

namespace util {
	template<typename T = uint32_t>
	class base_process {
	protected:
		HANDLE m_handle;
		int m_id;
		std::string m_name;

		std::unordered_map<std::string, uintptr_t> m_modules;
	public:
		base_process() = default;
		~base_process() = default;

		bool open() {
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

		bool read(const uintptr_t addr, void* data, size_t size) {
			static auto nt_read = g_syscalls.get<native::NtReadVirtualMemory>("NtReadVirtualMemory");

			ULONG read;
			auto status = nt_read(m_handle, reinterpret_cast<void*>(addr), data, size, &read);
			if (!NT_SUCCESS(status)) {
				io::log_error("failed to read at {:x}, status {:#X}.", addr, (status & 0xFFFFFFFF));
				return false;
			}

			return true;
		}

		bool write(const uintptr_t addr, void* data, size_t size) {
			static auto nt_write = g_syscalls.get<native::NtWiteVirtualMemory>("NtWriteVirtualMemory");

			ULONG wrote;
			auto status = nt_write(m_handle, reinterpret_cast<void*>(addr), data, size, &wrote);
			if (!NT_SUCCESS(status)) {
				io::log_error("failed to write to {}, status {:#X}.", m_name, (status & 0xFFFFFFFF));
				return false;
			}

			return true;
		}

		bool free(const uintptr_t addr, size_t size, uint32_t type = MEM_RELEASE) {
			static auto nt_free = g_syscalls.get<native::NtFreeVirtualMemory>("NtFreeVirtualMemory");

			SIZE_T win_size = size;
			void *addr_cast = reinterpret_cast<void*>(addr);
			auto status = nt_free(m_handle, &addr_cast, &win_size, MEM_RELEASE);
			if (!NT_SUCCESS(status)) {
				io::log_error("failed to free at {:x}, status {:#X}.", addr, (status & 0xFFFFFFFF));
				return false;
			}

			return true;
		}

		bool info(PROCESSINFOCLASS proc_info, void* data, size_t size) {
			static auto nt_proc_info = g_syscalls.get<native::NtQueryInformationProcess>("NtQueryInformationProcess");
			auto status = nt_proc_info(m_handle, proc_info, data, size, nullptr);
			if (!NT_SUCCESS(status)) {
				io::log_error("failed to query {} info, status {:#X}.", m_name, (status & 0xFFFFFFFF));
				return false;
			}

			return true;
		}

		bool thread(const uintptr_t func) {
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

		bool enum_modules() {
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

		bool close() {
			auto ret = util::close_handle(m_handle);
			if (ret) {
				io::log("closed handle to {}.", m_name);
			}
			m_handle = INVALID_HANDLE_VALUE;
			return ret;
		}

		uintptr_t peb() {
			bool is64 = sizeof(T) == sizeof(uint64_t);
			if (is64) {
				native::PROCESS_EXTENDED_BASIC_INFORMATION proc_info;
				proc_info.Size = sizeof(proc_info);
				if (!info(ProcessBasicInformation, &proc_info, sizeof(proc_info))) {
					return {};
				}
					
				return uintptr_t(proc_info.BasicInfo.PebBaseAddress);
			}

			uintptr_t addr;
			if (!info(ProcessWow64Information, &addr, sizeof(addr))) {
				return {};
			}

			return addr;
		}

		uintptr_t allocate(size_t size, uint32_t type, uint32_t protection) {
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

		auto &modules() { return m_modules; }
		auto &handle() { return m_handle; }
		auto &name() { return m_name; }
		auto &id() { return m_id; }
	};

	struct process_data_t {
		std::string name;
		int id;
	};

	struct thread_data_t {
		int id;
		uintptr_t handle;
		uint32_t state;
	};

	struct system_data_t {
		std::vector<process_data_t> processes;
		std::vector<thread_data_t> threads;
	};

	class process32 : public base_process<uint32_t> {
	public:
		process32(const process_data_t &data) {
			m_name = data.name;
			m_id = data.id;
		}

		uintptr_t module_export(const uintptr_t base, const std::string_view func);
		uintptr_t map(const std::string_view module_name);
	};

	class process64 : public base_process<uint64_t> {

	};

	struct handle_info_t {
		uint32_t access;
		uintptr_t handle;
		uint32_t obj_type;
	};

	bool fetch_system_data(system_data_t &out);
	bool fetch_process_handles(const int pid, std::vector<handle_info_t> &out);
};
