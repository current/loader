#pragma once

namespace native {
	struct PEB_LDR_DATA {
		uint32_t		Length;
		uint8_t			Initialized;
		uintptr_t		SsHandle;
		LIST_ENTRY		InLoadOrderModuleList;
		LIST_ENTRY		InMemoryOrderModuleList;
		LIST_ENTRY		InInitializationOrderModuleList;
		uintptr_t		EntryInProgress;
		uint8_t			ShutdownInProgress;
		uintptr_t		ShutdownThreadId;
	};

	struct UNICODE_STRING {
		uint16_t	Length;
		uint16_t	MaximumLength;
		wchar_t		*Buffer;
	};

	struct STRING {
		uint16_t	Length;
		uint16_t	MaximumLength;
		char		*Buffer;
	};

	struct _PEB {
		uint8_t							InheritedAddressSpace;
		uint8_t							ReadImageFileExecOptions;
		uint8_t							BeingDebugged;
		uint8_t							BitField;
		uintptr_t						Mutant;
		uintptr_t						ImageBaseAddress;
		PEB_LDR_DATA					*Ldr;
		uintptr_t		                ProcessParameters;
		uintptr_t						SubSystemData;
		uintptr_t						ProcessHeap;
		uintptr_t			            FastPebLock;
		uintptr_t						AtlThunkSListPtr;
		uintptr_t						IFEOKey;
		uintptr_t						CrossProcessFlags;
		union {
			uintptr_t						KernelCallbackTable;
			uintptr_t						UserSharedInfoPtr;
		};
		uint32_t						SystemReserved;
		uint32_t						AtlThunkSListPtr32;
		uintptr_t						ApiSetMap;
	};

	struct LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY				InLoadOrderLinks;
		LIST_ENTRY				InMemoryOrderLinks;
		LIST_ENTRY				InInitializationOrderLinks;
		uintptr_t				DllBase;
		uintptr_t				EntryPoint;
		uint32_t				SizeOfImage;
		UNICODE_STRING			FullDllName;
		UNICODE_STRING			BaseDllName;
	};

	template<class P>
	struct peb_t {
		uint8_t _ignored[2];
		uint8_t being_debugged;
		uint8_t bitfield;
		P            _ignored2[2];
		P            Ldr;
	};

	template<class P>
	struct list_entry_t {
		P Flink;
		P Blink;
	};

	template<class P>
	struct peb_ldr_data_t {
		unsigned long   Length;
		bool            Initialized;
		P               SsHandle;
		list_entry_t<P> InLoadOrderModuleList;
	};

	template<class P>
	struct unicode_string_t {
		uint16_t Length;
		uint16_t MaximumLength;
		P             Buffer;
	};

	template<class P>
	struct ldr_data_table_entry_t {
		list_entry_t<P> InLoadOrderLinks;
		list_entry_t<P> InMemoryOrderLinks;
		union {
			list_entry_t<P> InInitializationOrderLinks;
			list_entry_t<P> InProgressLinks;
		};
		P                   DllBase;
		P                   EntryPoint;
		unsigned long       SizeOfImage;
		unicode_string_t<P> FullDllName;
	};

	typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
		USHORT UniqueProcessId;
		USHORT CreatorBackTraceIndex;
		UCHAR ObjectTypeIndex;
		UCHAR HandleAttributes;
		USHORT HandleValue;
		PVOID Object;
		ULONG GrantedAccess;
	} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

	typedef struct _SYSTEM_HANDLE_INFORMATION {
		ULONG NumberOfHandles;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
	} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

	struct API_SET_VALUE_ENTRY {
		ULONG Flags;
		ULONG NameOffset;
		ULONG NameLength;
		ULONG ValueOffset;
		ULONG ValueLength;
	};

	struct API_SET_VALUE_ARRAY {
		ULONG Flags;
		ULONG NameOffset;
		ULONG Unk;
		ULONG NameLength;
		ULONG DataOffset;
		ULONG Count;
	};

	struct API_SET_NAMESPACE_ENTRY {
		ULONG Limit;
		ULONG Size;
	};

	struct API_SET_NAMESPACE_ARRAY {
		ULONG Version;
		ULONG Size;
		ULONG Flags;
		ULONG Count;
		ULONG Start;
		ULONG End;
		ULONG Unk[2];
	};

	struct PROCESS_EXTENDED_BASIC_INFORMATION {
		SIZE_T Size; // set to sizeof structure on input
		PROCESS_BASIC_INFORMATION BasicInfo;
		uint8_t Flags;
	};

	using NtQuerySystemInformation = NTSTATUS(__stdcall*)(SYSTEM_INFORMATION_CLASS, PVOID, SIZE_T, PULONG);
	using NtOpenProcess = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
	using NtOpenThread = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*);
	using NtReadVirtualMemory = NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, SIZE_T, PULONG);
	using NtAllocateVirtualMemory = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
	using NtWriteVirtualMemory = NTSTATUS(__stdcall*)(HANDLE, PVOID, PVOID, ULONG, PULONG);
	using NtClose = NTSTATUS(__stdcall*)(HANDLE);
	using NtFreeVirtualMemory = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
	using NtQueryInformationProcess = NTSTATUS(__stdcall*)(HANDLE, PROCESSINFOCLASS, PVOID, SIZE_T, PULONG);
	using NtWaitForSingleObject = NTSTATUS(__stdcall*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
	using NtCreateThreadEx = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, LPTHREAD_START_ROUTINE, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
	using NtGetContextThread = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);

};  // namespace native