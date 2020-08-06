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

	enum PROCESSINFOCLASS
	{
		ProcessBasicInformation, // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
		ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
		ProcessIoCounters, // q: IO_COUNTERS
		ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
		ProcessTimes, // q: KERNEL_USER_TIMES
		ProcessBasePriority, // s: KPRIORITY
		ProcessRaisePriority, // s: ULONG
		ProcessDebugPort, // q: HANDLE
		ProcessExceptionPort, // s: PROCESS_EXCEPTION_PORT
		ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
		ProcessLdtInformation, // qs: PROCESS_LDT_INFORMATION // 10
		ProcessLdtSize, // s: PROCESS_LDT_SIZE
		ProcessDefaultHardErrorMode, // qs: ULONG
		ProcessIoPortHandlers, // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
		ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
		ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
		ProcessUserModeIOPL, // qs: ULONG (requires SeTcbPrivilege)
		ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
		ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
		ProcessWx86Information, // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
		ProcessHandleCount, // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
		ProcessAffinityMask, // s: KAFFINITY
		ProcessPriorityBoost, // qs: ULONG
		ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
		ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
		ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
		ProcessWow64Information, // q: ULONG_PTR
		ProcessImageFileName, // q: UNICODE_STRING
		ProcessLUIDDeviceMapsEnabled, // q: ULONG
		ProcessBreakOnTermination, // qs: ULONG
		ProcessDebugObjectHandle, // q: HANDLE // 30
		ProcessDebugFlags, // qs: ULONG
		ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
		ProcessIoPriority, // qs: IO_PRIORITY_HINT
		ProcessExecuteFlags, // qs: ULONG
		ProcessResourceManagement, // ProcessTlsInformation // PROCESS_TLS_INFORMATION
		ProcessCookie, // q: ULONG
		ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
		ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
		ProcessPagePriority, // q: PAGE_PRIORITY_INFORMATION
		ProcessInstrumentationCallback, // qs: PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
		ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
		ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
		ProcessImageFileNameWin32, // q: UNICODE_STRING
		ProcessImageFileMapping, // q: HANDLE (input)
		ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
		ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
		ProcessGroupInformation, // q: USHORT[]
		ProcessTokenVirtualizationEnabled, // s: ULONG
		ProcessConsoleHostProcess, // q: ULONG_PTR // ProcessOwnerInformation
		ProcessWindowInformation, // q: PROCESS_WINDOW_INFORMATION // 50
		ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
		ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
		ProcessDynamicFunctionTableInformation,
		ProcessHandleCheckingMode, // qs: ULONG; s: 0 disables, otherwise enables
		ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
		ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
		ProcessWorkingSetControl, // s: PROCESS_WORKING_SET_CONTROL
		ProcessHandleTable, // q: ULONG[] // since WINBLUE
		ProcessCheckStackExtentsMode,
		ProcessCommandLineInformation, // q: UNICODE_STRING // 60
		ProcessProtectionInformation, // q: PS_PROTECTION
		ProcessMemoryExhaustion, // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
		ProcessFaultInformation, // PROCESS_FAULT_INFORMATION
		ProcessTelemetryIdInformation, // PROCESS_TELEMETRY_ID_INFORMATION
		ProcessCommitReleaseInformation, // PROCESS_COMMIT_RELEASE_INFORMATION
		ProcessDefaultCpuSetsInformation,
		ProcessAllowedCpuSetsInformation,
		ProcessSubsystemProcess,
		ProcessJobMemoryInformation, // PROCESS_JOB_MEMORY_INFO
		ProcessInPrivate, // since THRESHOLD2 // 70
		ProcessRaiseUMExceptionOnInvalidHandleClose, // qs: ULONG; s: 0 disables, otherwise enables
		ProcessIumChallengeResponse,
		ProcessChildProcessInformation, // PROCESS_CHILD_PROCESS_INFORMATION
		ProcessHighGraphicsPriorityInformation,
		ProcessSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
		ProcessEnergyValues, // PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
		ProcessActivityThrottleState, // PROCESS_ACTIVITY_THROTTLE_STATE
		ProcessActivityThrottlePolicy, // PROCESS_ACTIVITY_THROTTLE_POLICY
		ProcessWin32kSyscallFilterInformation,
		ProcessDisableSystemAllowedCpuSets, // 80
		ProcessWakeInformation, // PROCESS_WAKE_INFORMATION
		ProcessEnergyTrackingState, // PROCESS_ENERGY_TRACKING_STATE
		ProcessManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
		ProcessCaptureTrustletLiveDump,
		ProcessTelemetryCoverage,
		ProcessEnclaveInformation,
		ProcessEnableReadWriteVmLogging, // PROCESS_READWRITEVM_LOGGING_INFORMATION
		ProcessUptimeInformation, // PROCESS_UPTIME_INFORMATION
		ProcessImageSection, // q: HANDLE
		ProcessDebugAuthInformation, // since REDSTONE4 // 90
		ProcessSystemResourceManagement, // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
		ProcessSequenceNumber, // q: ULONGLONG
		ProcessLoaderDetour, // since REDSTONE5
		ProcessSecurityDomainInformation, // PROCESS_SECURITY_DOMAIN_INFORMATION
		ProcessCombineSecurityDomainsInformation, // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
		ProcessEnableLogging, // PROCESS_LOGGING_INFORMATION
		ProcessLeapSecondInformation, // PROCESS_LEAP_SECOND_INFORMATION
		ProcessFiberShadowStackAllocation, // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
		ProcessFreeFiberShadowStackAllocation, // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
		ProcessAltSystemCallInformation, // since 20H1 // 100
		ProcessDynamicEHContinuationTargets, // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
		MaxProcessInfoClass
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

};  // namespace native