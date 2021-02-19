#pragma once
#include <Windows.h>

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION1 // Size=184
{
	ULONG NextEntryOffset; // Size=4 Offset=0
	ULONG NumberOfThreads; // Size=4 Offset=4
	LARGE_INTEGER WorkingSetPrivateSize; // Size=8 Offset=8
	ULONG HardFaultCount; // Size=4 Offset=16
	ULONG NumberOfThreadsHighWatermark; // Size=4 Offset=20
	ULONGLONG CycleTime; // Size=8 Offset=24
	LARGE_INTEGER CreateTime; // Size=8 Offset=32
	LARGE_INTEGER UserTime; // Size=8 Offset=40
	LARGE_INTEGER KernelTime; // Size=8 Offset=48
	UNICODE_STRING ImageName; // Size=8 Offset=56
	LONG BasePriority; // Size=4 Offset=64
	PVOID UniqueProcessId; // Size=4 Offset=68
	PVOID InheritedFromUniqueProcessId; // Size=4 Offset=72
	ULONG HandleCount; // Size=4 Offset=76
	ULONG SessionId; // Size=4 Offset=80
	ULONG UniqueProcessKey; // Size=4 Offset=84
	ULONG PeakVirtualSize; // Size=4 Offset=88
	ULONG VirtualSize; // Size=4 Offset=92
	ULONG PageFaultCount; // Size=4 Offset=96
	ULONG PeakWorkingSetSize; // Size=4 Offset=100
	ULONG WorkingSetSize; // Size=4 Offset=104
	ULONG QuotaPeakPagedPoolUsage; // Size=4 Offset=108
	ULONG QuotaPagedPoolUsage; // Size=4 Offset=112
	ULONG QuotaPeakNonPagedPoolUsage; // Size=4 Offset=116
	ULONG QuotaNonPagedPoolUsage; // Size=4 Offset=120
	ULONG PagefileUsage; // Size=4 Offset=124
	ULONG PeakPagefileUsage; // Size=4 Offset=128
	ULONG PrivatePageCount; // Size=4 Offset=132
	LARGE_INTEGER ReadOperationCount; // Size=8 Offset=136
	LARGE_INTEGER WriteOperationCount; // Size=8 Offset=144
	LARGE_INTEGER OtherOperationCount; // Size=8 Offset=152
	LARGE_INTEGER ReadTransferCount; // Size=8 Offset=160
	LARGE_INTEGER WriteTransferCount; // Size=8 Offset=168
	LARGE_INTEGER OtherTransferCount; // Size=8 Offset=176
} SYSTEM_PROCESS_INFORMATION1;

typedef struct _PEB1
{
     UCHAR InheritedAddressSpace;
     UCHAR ReadImageFileExecOptions;
     UCHAR BeingDebugged;
     UCHAR BitField;
     ULONG ImageUsesLargePages: 1;
     ULONG IsProtectedProcess: 1;
     ULONG IsLegacyProcess: 1;
     ULONG IsImageDynamicallyRelocated: 1;
     ULONG SpareBits: 4;
     PVOID Mutant;
     PVOID ImageBaseAddress;
     PPEB_LDR_DATA Ldr;
     PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
} PEB1, *PPEB1;

typedef struct PEB_LDR_DATA1 {
	ULONG      Length;
	BOOLEAN    Initialized;
	PVOID      SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA1, *PPEB_LDR_DATA1;

typedef struct _LDR_DATA_TABLE_ENTRY1
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID EntryPointActivationContext;
	PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY1, *PLDR_DATA_TABLE_ENTRY1;

typedef struct _PROCESS_BASIC_INFORMATION1 {
	PVOID Reserved1;
	PPEB1 PebBaseAddress;
	PVOID Reserved2[2];
	ULONG_PTR UniqueProcessId;
	PVOID Reserved3;
} PROCESS_BASIC_INFORMATION1;

BOOL read_process_memory(DWORD id, UINT64 addr, void* buf, size_t size);

#define MAX_MODULES 0x2710

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
	__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout PVOID SystemInformation,
	__in ULONG SystemInformationLength,
	__out_opt PULONG ReturnLength
	);


typedef NTSTATUS(NTAPI* PNtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

PNtQueryInformationProcess My_NtQueryInformationProcess;

#define ASSERT(a)

static const WCHAR S_DotSoW[] = { '.','s','o','\0' };
const WCHAR        S_ElfW[] = { '<','e','l','f','>','\0' };

static const WCHAR S_AcmW[] = { '.','a','c','m','\0' };
static const WCHAR S_DllW[] = { '.','d','l','l','\0' };
static const WCHAR S_DrvW[] = { '.','d','r','v','\0' };
static const WCHAR S_ExeW[] = { '.','e','x','e','\0' };
static const WCHAR S_OcxW[] = { '.','o','c','x','\0' };
static const WCHAR S_VxdW[] = { '.','v','x','d','\0' };
static const WCHAR* const ext[] = { S_AcmW, S_DllW, S_DrvW, S_ExeW, S_OcxW, S_VxdW, NULL };
