#include <iostream>
#include <Windows.h>
#include <process.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include "minidump.h"
#include"syscall.h"
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Version.lib")
#include "MhyDrvIO.h"
MhyDrvIO* pdrvCtl1;

static BOOL NTAPI FindModule(IN HANDLE hProcess,IN HMODULE hModule OPTIONAL,OUT PLDR_DATA_TABLE_ENTRY1 Module)
{
	DWORD Count;
	NTSTATUS Status;
	PPEB_LDR_DATA LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION1 ProcInfo;

	/* Query the process information to get its PEB address */
	Status = My_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcInfo, sizeof(ProcInfo), NULL);
	if (!NT_SUCCESS(Status))
	{
		//SetLastError(RtlNtStatusToDosError(Status));
		printf("SetLastError(RtlNtStatusToDosError(Status));");
		return FALSE;
	}

	/* If no module was provided, get base as module */
	if (hModule == NULL)
	{
		//read_process_memory(GetProcessId(hProcess)
		//if (!ReadProcessMemory(hProcess, &ProcInfo.PebBaseAddress->ImageBaseAddress, &hModule, sizeof(hModule), NULL))
		if (!read_process_memory(GetProcessId(hProcess), (UINT64)(&ProcInfo.PebBaseAddress->ImageBaseAddress), &hModule, sizeof(hModule)))
		{
			return FALSE;
		}
	}

	/* Read loader data address from PEB */
	//if (!ReadProcessMemory(hProcess, &ProcInfo.PebBaseAddress->Ldr, &LoaderData, sizeof(LoaderData), NULL))
	if (!read_process_memory(GetProcessId(hProcess), (UINT64)(&ProcInfo.PebBaseAddress->Ldr), &LoaderData, sizeof(LoaderData)))
	{
		return FALSE;
	}

	if (LoaderData == NULL)
	{
		SetLastError(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	/* Store list head address */
	ListHead = &(LoaderData->InMemoryOrderModuleList);

	/* Read first element in the modules list */
	//if (!ReadProcessMemory(hProcess,
	if (!read_process_memory(GetProcessId(hProcess),
		(UINT64)(&(LoaderData->InMemoryOrderModuleList.Flink)),
		&ListEntry,
		sizeof(ListEntry)))
	{
		return FALSE;
	}

	Count = 0;

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		//if (!ReadProcessMemory(hProcess,
		if (!read_process_memory(GetProcessId(hProcess),
			(UINT64)CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY1, InMemoryOrderModuleList),
			Module,
			sizeof(*Module)))
		{
			return FALSE;
		}

		/* Does that match the module we're looking for? */
		if (Module->DllBase == hModule)
		{
			return TRUE;
		}

		++Count;
		if (Count > MAX_MODULES)
		{
			break;
		}

		/* Get to next listed module */
		ListEntry = Module->InMemoryOrderModuleList.Flink;
	}

	SetLastError(ERROR_INVALID_HANDLE);
	return FALSE;
}

BOOL fetch_process_info(struct dump_context* dc)
{
	ULONG       buf_size = 0x1000;
	NTSTATUS    nts;
	SYSTEM_PROCESS_INFORMATION1* pcs_buffer;

	if (!(pcs_buffer = (SYSTEM_PROCESS_INFORMATION1*)HeapAlloc(GetProcessHeap(), 0, buf_size)))
		return FALSE;

	for (;;)
	{
		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (!hNtdll) return 0;
		PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
		if (NtQuerySystemInformation == NULL) return 0;
		nts = NtQuerySystemInformation(SystemProcessInformation, pcs_buffer, buf_size, NULL);
		if (nts != 0xC0000004L)
			break;

		pcs_buffer = (SYSTEM_PROCESS_INFORMATION1*)HeapReAlloc(GetProcessHeap(), 0, pcs_buffer, buf_size *= 2);
		if (!pcs_buffer)
			return FALSE;
	}

	if (nts == 0)
	{
		SYSTEM_PROCESS_INFORMATION1* spi = pcs_buffer;

		for (;;)
		{
			if (HandleToUlong(spi->UniqueProcessId) == dc->pid)
			{
				dc->num_threads = spi->NumberOfThreads;
				dc->threads = (dump_thread*)HeapAlloc(GetProcessHeap(), 0, dc->num_threads * sizeof(dc->threads[0]));
				if (!dc->threads)
					goto failed;

				HeapFree(GetProcessHeap(), 0, pcs_buffer);
				return TRUE;
			}

			if (!spi->NextEntryOffset)
				break;

			spi = (SYSTEM_PROCESS_INFORMATION1*)((char*)spi + spi->NextEntryOffset);
		}
	}

failed:
	HeapFree(GetProcessHeap(), 0, pcs_buffer);
	return FALSE;
}

void writeat(struct dump_context* dc, RVA rva, const void* data, unsigned size)
{
	DWORD written;

	SetFilePointer(dc->hFile, rva, NULL, FILE_BEGIN);
	WriteFile(dc->hFile, data, size, &written, NULL);
}

void append(struct dump_context* dc, const void* data, unsigned size)
{
	writeat(dc, dc->rva, data, size);
	dc->rva += size;
}

unsigned dump_system_info(struct dump_context* dc)
{
	MINIDUMP_SYSTEM_INFO        mdSysInfo;
	SYSTEM_INFO                 sysInfo;
	OSVERSIONINFOW              osInfo;
	DWORD                       written;
	ULONG                       slen;
	DWORD                       wine_extra = 0;

	const char* build_id = NULL;
	const char* sys_name = NULL;
	const char* release_name = NULL;

	GetSystemInfo(&sysInfo);
	osInfo.dwOSVersionInfoSize = sizeof(osInfo);

	typedef int(WINAPI* RtlGetNtVersionNumbers)(PDWORD, PDWORD, PDWORD);

	HINSTANCE hinst = LoadLibrary("ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	RtlGetNtVersionNumbers proc = (RtlGetNtVersionNumbers)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);
	dwBuildNumber &= 0xffff;
	printf("OS Version: %d.%d.%d\n", dwMajor, dwMinor, dwBuildNumber);
	FreeLibrary(hinst);

	mdSysInfo.ProcessorArchitecture = sysInfo.wProcessorArchitecture;
	mdSysInfo.ProcessorLevel = sysInfo.wProcessorLevel;
	mdSysInfo.ProcessorRevision = sysInfo.wProcessorRevision;
	mdSysInfo.NumberOfProcessors = (UCHAR)sysInfo.dwNumberOfProcessors;
	mdSysInfo.ProductType = VER_NT_WORKSTATION; /* This might need fixing */
	mdSysInfo.MajorVersion = dwMajor;
	mdSysInfo.MinorVersion = dwMinor;
	mdSysInfo.BuildNumber = dwBuildNumber;
	mdSysInfo.PlatformId = 0x2;

	mdSysInfo.CSDVersionRva = dc->rva + sizeof(mdSysInfo) + wine_extra;
	mdSysInfo.Reserved1 = 0;
	mdSysInfo.SuiteMask = VER_SUITE_TERMINAL;

	unsigned        i;
	ULONG64         one = 1;

	mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] = 0;
	mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[1] = 0;

	for (i = 0; i < sizeof(mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0]) * 8; i++)
		if (IsProcessorFeaturePresent(i))
			mdSysInfo.Cpu.OtherCpuInfo.ProcessorFeatures[0] |= one << i;

	append(dc, &mdSysInfo, sizeof(mdSysInfo));

	const WCHAR* szCSDVersion = L"";
	slen = lstrlenW(szCSDVersion) * sizeof(WCHAR);
	WriteFile(dc->hFile, &slen, sizeof(slen), &written, NULL);
	WriteFile(dc->hFile, szCSDVersion, slen, &written, NULL);
	dc->rva += sizeof(ULONG) + slen;

	return sizeof(mdSysInfo);
}

void minidump_add_memory_block(struct dump_context* dc, ULONG64 base, ULONG size, ULONG rva)
{
	if (!dc->mem)
	{
		dc->alloc_mem = 32;
		dc->mem = (dump_memory*)HeapAlloc(GetProcessHeap(), 0, dc->alloc_mem * sizeof(*dc->mem));
	}
	else if (dc->num_mem >= dc->alloc_mem)
	{
		dc->alloc_mem *= 2;
		dc->mem = (dump_memory*)HeapReAlloc(GetProcessHeap(), 0, dc->mem, dc->alloc_mem * sizeof(*dc->mem));
	}
	if (dc->mem)
	{
		dc->mem[dc->num_mem].base = base;
		dc->mem[dc->num_mem].size = size;
		dc->mem[dc->num_mem].rva = rva;
		dc->num_mem++;
	}
	else
		dc->num_mem = dc->alloc_mem = 0;
}

void minidump_add_memory64_block(struct dump_context* dc, ULONG64 base, ULONG64 size)
{
	if (!dc->mem64)
	{
		dc->alloc_mem64 = 32;
		dc->mem64 =(dump_memory64*) HeapAlloc(GetProcessHeap(), 0, dc->alloc_mem64 * sizeof(*dc->mem64));
	}
	else if (dc->num_mem64 >= dc->alloc_mem64)
	{
		dc->alloc_mem64 *= 2;
		dc->mem64 = (dump_memory64*)HeapReAlloc(GetProcessHeap(), 0, dc->mem64, dc->alloc_mem64 * sizeof(*dc->mem64));
	}
	if (dc->mem64)
	{
		dc->mem64[dc->num_mem64].base = base;
		dc->mem64[dc->num_mem64].size = size;
		dc->num_mem64++;
	}
	else
		dc->num_mem64 = dc->alloc_mem64 = 0;
}

void fetch_memory64_info(struct dump_context* dc)
{
	ULONG_PTR                   addr;
	MEMORY_BASIC_INFORMATION    mbi;

	addr = 0;
	while (VirtualQueryEx(dc->handle, (LPCVOID)addr, &mbi, sizeof(mbi)) != 0)
	{
		/* Memory regions with state MEM_COMMIT will be added to the dump */
		if (mbi.State == MEM_COMMIT)
			minidump_add_memory64_block(dc, (ULONG_PTR)mbi.BaseAddress, mbi.RegionSize);

		if ((addr + mbi.RegionSize) < addr)
			break;

		addr = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
	}
}

BOOL read_process_memory(DWORD id, UINT64 addr, void* buf, size_t size)
{
	NTSTATUS res =(pdrvCtl1->ReadProcMem(id, addr, size, buf));
	//if (!res)
	//{
	//	printf("成功\n");
	//}
	//else
	//{
	//	printf("失败\n");
	//}
	return !res;
}

unsigned dump_memory64_info(struct dump_context* dc)
{
	MINIDUMP_MEMORY64_LIST          mdMem64List;
	MINIDUMP_MEMORY_DESCRIPTOR64    mdMem64;
	DWORD                           written;
	unsigned                        i, len, sz;
	RVA                             rva_base;
	char                            tmp[1024];
	ULONG64                         pos;
	LARGE_INTEGER                   filepos;

	sz = sizeof(mdMem64List.NumberOfMemoryRanges) + sizeof(mdMem64List.BaseRva) + dc->num_mem64 * sizeof(mdMem64);

	mdMem64List.NumberOfMemoryRanges = dc->num_mem64;
	mdMem64List.BaseRva = dc->rva + sz;

	append(dc, &mdMem64List.NumberOfMemoryRanges, sizeof(mdMem64List.NumberOfMemoryRanges));
	append(dc, &mdMem64List.BaseRva, sizeof(mdMem64List.BaseRva));

	rva_base = dc->rva;
	dc->rva += dc->num_mem64 * sizeof(mdMem64);

	/* dc->rva is not updated past this point. The end of the dump
	 * is just the full memory data. */
	filepos.QuadPart = dc->rva;
	for (i = 0; i < dc->num_mem64; i++)
	{
		mdMem64.StartOfMemoryRange = dc->mem64[i].base;
		mdMem64.DataSize = dc->mem64[i].size;
		SetFilePointerEx(dc->hFile, filepos, NULL, FILE_BEGIN);
		for (pos = 0; pos < dc->mem64[i].size; pos += sizeof(tmp))
		{
			len = (unsigned)(min(dc->mem64[i].size - pos, sizeof(tmp)));
			if (read_process_memory(dc->pid, dc->mem64[i].base + pos, tmp, len))
				WriteFile(dc->hFile, tmp, len, &written, NULL);
		}
		filepos.QuadPart += mdMem64.DataSize;
		writeat(dc, rva_base + i * sizeof(mdMem64), &mdMem64, sizeof(mdMem64));
	}

	return sz;
}

void fetch_module_versioninfo(LPCWSTR filename, VS_FIXEDFILEINFO* ffi)
{
	DWORD       handle;
	DWORD       sz;
	static const WCHAR backslashW[] = { '\\', '\0' };

	memset(ffi, 0, sizeof(*ffi));
	if ((sz = GetFileVersionInfoSizeW(filename, &handle)))
	{
		void* info = HeapAlloc(GetProcessHeap(), 0, sz);
		if (info && GetFileVersionInfoW(filename, handle, sz, info))
		{
			VS_FIXEDFILEINFO* ptr;
			UINT    len;

			if (VerQueryValueW(info, backslashW, (LPVOID*)&ptr, &len))
				memcpy(ffi, ptr, min(len, sizeof(*ffi)));
		}
		HeapFree(GetProcessHeap(), 0, info);
	}
}

unsigned dump_modules(struct dump_context* dc, BOOL dump_elf)
{
	MINIDUMP_MODULE             mdModule;
	MINIDUMP_MODULE_LIST        mdModuleList;
	char                        tmp[1024];
	MINIDUMP_STRING* ms = (MINIDUMP_STRING*)tmp;
	ULONG                       i, nmod;
	RVA                         rva_base;
	DWORD                       flags_out;
	unsigned                    sz;

	for (i = nmod = 0; i < dc->num_modules; i++)
	{
		if ((dc->modules[i].is_elf && dump_elf) ||
			(!dc->modules[i].is_elf && !dump_elf))
			nmod++;
	}

	mdModuleList.NumberOfModules = 0;
	rva_base = dc->rva;
	dc->rva += sz = sizeof(mdModuleList.NumberOfModules) + sizeof(mdModule) * nmod;

	for (i = 0; i < dc->num_modules; i++)
	{
		if ((dc->modules[i].is_elf && !dump_elf) ||
			(!dc->modules[i].is_elf && dump_elf))
			continue;

		flags_out = ModuleWriteModule | ModuleWriteMiscRecord | ModuleWriteCvRecord;
		if (dc->type & MiniDumpWithDataSegs)
			flags_out |= ModuleWriteDataSeg;
		if (dc->type & MiniDumpWithProcessThreadData)
			flags_out |= ModuleWriteTlsData;
		if (dc->type & MiniDumpWithCodeSegs)
			flags_out |= ModuleWriteCodeSegs;

		ms->Length = (lstrlenW(dc->modules[i].name) + 1) * sizeof(WCHAR);

		lstrcpyW(ms->Buffer, dc->modules[i].name);

		if (flags_out & ModuleWriteModule)
		{
			mdModule.BaseOfImage = dc->modules[i].base;
			mdModule.SizeOfImage = dc->modules[i].size;
			mdModule.CheckSum = dc->modules[i].checksum;
			mdModule.TimeDateStamp = dc->modules[i].timestamp;
			mdModule.ModuleNameRva = dc->rva;
			ms->Length -= sizeof(WCHAR);
			append(dc, ms, sizeof(ULONG) + ms->Length + sizeof(WCHAR));
			fetch_module_versioninfo(ms->Buffer, &mdModule.VersionInfo);
			mdModule.CvRecord.DataSize = 0;
			mdModule.CvRecord.Rva = 0;
			mdModule.MiscRecord.DataSize = 0;
			mdModule.MiscRecord.Rva = 0;
			mdModule.Reserved0 = 0;
			mdModule.Reserved1 = 0;
			writeat(dc,
				rva_base + sizeof(mdModuleList.NumberOfModules) +
				mdModuleList.NumberOfModules++ * sizeof(mdModule),
				&mdModule, sizeof(mdModule));
		}
	}
	writeat(dc, rva_base, &mdModuleList.NumberOfModules, sizeof(mdModuleList.NumberOfModules));

	return sz;
}

BOOL validate_addr64(DWORD64 addr)
{
	if (sizeof(void*) == sizeof(int) && (addr >> 32))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	return TRUE;
}

BOOL pe_load_nt_header(DWORD hProc, DWORD64 base, IMAGE_NT_HEADERS* nth)
{
	IMAGE_DOS_HEADER    dos;

	NTSTATUS res = read_process_memory(hProc, base, &dos, sizeof(dos));
	NTSTATUS res2 = read_process_memory(hProc, (base + dos.e_lfanew), nth, sizeof(*nth));

	return  res && dos.e_magic == IMAGE_DOS_SIGNATURE && res2 && nth->Signature == IMAGE_NT_SIGNATURE;
}

DWORD WINAPI myGetModuleFileNameExW(HANDLE hProcess,HMODULE hModule,LPWSTR lpFilename,DWORD nSize)
{
	DWORD Len;
	LDR_DATA_TABLE_ENTRY1 Module;

	/* Get the matching module */
	if (!FindModule(hProcess, hModule, &Module))
	{
		return 0;
	}

	/* Get the maximum len we have/can write in given size */
	Len = Module.FullDllName.Length + sizeof(UNICODE_NULL);
	if (nSize * sizeof(WCHAR) < Len)
	{
		Len = nSize * sizeof(WCHAR);
	}

	/* Read string */
	//if (!ReadProcessMemory(hProcess, (&Module.FullDllName)->Buffer, lpFilename, Len, NULL))
	if (!read_process_memory(GetProcessId(hProcess), (UINT64)(&Module.FullDllName)->Buffer, lpFilename, Len))
	{
		return 0;
	}

	/* If we are at the end of the string, prepare to override to nullify string */
	if (Len == Module.FullDllName.Length + sizeof(UNICODE_NULL))
	{
		Len -= sizeof(UNICODE_NULL);
	}

	/* Nullify at the end if needed */
	if (Len >= nSize * sizeof(WCHAR))
	{
		if (nSize)
		{
			ASSERT(nSize >= sizeof(UNICODE_NULL));
			lpFilename[nSize - 1] = UNICODE_NULL;
		}
	}
	/* Otherwise, nullify at last written char */
	else
	{
		ASSERT(Len + sizeof(UNICODE_NULL) <= nSize * sizeof(WCHAR));
		lpFilename[Len / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return Len / sizeof(WCHAR);
}

BOOL add_module(struct dump_context* dc, const WCHAR* name, DWORD64 base, DWORD size, DWORD timestamp, DWORD checksum, BOOL is_elf)
{
	if (!dc->modules)
	{
		dc->alloc_modules = 32;
		dc->modules = (dump_module*)HeapAlloc(GetProcessHeap(), 0, dc->alloc_modules * sizeof(*dc->modules));
	}
	else if (dc->num_modules >= dc->alloc_modules)
	{
		dc->alloc_modules *= 2;
		dc->modules = (dump_module*)HeapReAlloc(GetProcessHeap(), 0, dc->modules, dc->alloc_modules * sizeof(*dc->modules));
	}
	if (!dc->modules)
	{
		dc->alloc_modules = dc->num_modules = 0;
		return FALSE;
	}

	myGetModuleFileNameExW(dc->handle, (HMODULE)(DWORD_PTR)base, dc->modules[dc->num_modules].name, ARRAY_SIZE(dc->modules[dc->num_modules].name));

	dc->modules[dc->num_modules].base = base;
	dc->modules[dc->num_modules].size = size;
	dc->modules[dc->num_modules].timestamp = timestamp;
	dc->modules[dc->num_modules].checksum = checksum;
	dc->modules[dc->num_modules].is_elf = is_elf;
	dc->num_modules++;

	return TRUE;
}

BOOL fetch_pe_module_info_cb(PCWSTR name, DWORD64 base, ULONG size, PVOID user)
{
	struct dump_context* dc = (dump_context*)user;
	IMAGE_NT_HEADERS            nth;

	if (!validate_addr64(base))
		return FALSE;

	if (pe_load_nt_header(dc->pid, base, &nth))
		add_module((dump_context*)user, name, base, size, nth.FileHeader.TimeDateStamp, nth.OptionalHeader.CheckSum, FALSE);

	return TRUE;
}

BOOL WINAPI my_EnumProcessModules(HANDLE hProcess,HMODULE *lphModule,DWORD cb,LPDWORD lpcbNeeded)
{
	NTSTATUS Status;
	DWORD NbOfModules, Count;
	PPEB_LDR_DATA1 LoaderData;
	PLIST_ENTRY ListHead, ListEntry;
	PROCESS_BASIC_INFORMATION ProcInfo;
	LDR_DATA_TABLE_ENTRY1 CurrentModule;
	

	My_NtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(LoadLibraryA("Ntdll.dll"), "NtQueryInformationProcess");
	/* Query the process information to get its PEB address */
	Status = My_NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcInfo, sizeof(ProcInfo), NULL);
	if (!NT_SUCCESS(Status))
	{
		//SetLastError(RtlNtStatusToDosError(Status));
		printf("SetLastError(RtlNtStatusToDosError(Status))");
		return FALSE;
	}

	if (ProcInfo.PebBaseAddress == NULL)
	{
		printf("SetLastError(RtlNtStatusToDosError(STATUS_PARTIAL_COPY))");
		//SetLastError(RtlNtStatusToDosError(STATUS_PARTIAL_COPY));
		return FALSE;
	}
	//read_process_memory GetProcessId

	/* Read loader data address from PEB */
	//if (!ReadProcessMemory(hProcess, &ProcInfo.PebBaseAddress->Ldr, &LoaderData, sizeof(LoaderData), NULL))
	if (!read_process_memory(GetProcessId(hProcess), (UINT64)(&ProcInfo.PebBaseAddress->Ldr), &LoaderData, sizeof(LoaderData)))
	{
		return FALSE;
	}

	/* Store list head address */
	ListHead = &LoaderData->InLoadOrderModuleList;

	/* Read first element in the modules list */
	//if (!ReadProcessMemory(hProcess, &LoaderData->InLoadOrderModuleList.Flink, &ListEntry, sizeof(ListEntry), NULL))
	if (!read_process_memory(GetProcessId(hProcess), (UINT64)(&LoaderData->InLoadOrderModuleList.Flink), &ListEntry, sizeof(ListEntry)))
	{
		return FALSE;
	}

	NbOfModules = cb / sizeof(HMODULE);
	Count = 0;

	/* Loop on the modules */
	while (ListEntry != ListHead)
	{
		/* Load module data */
		//if (!ReadProcessMemory(hProcess,
		if (!read_process_memory(GetProcessId(hProcess),
			(UINT64)CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY1, InLoadOrderLinks),
			&CurrentModule,
			sizeof(CurrentModule)))
		{
			return FALSE;
		}

		/* Check if we can output module, do it if so */
		if (Count < NbOfModules)
		{
			lphModule[Count] = (HMODULE)CurrentModule.DllBase;
		}

		++Count;
		if (Count > MAX_MODULES)
		{
			SetLastError(ERROR_INVALID_HANDLE);
			return FALSE;
		}

		/* Get to next listed module */
		ListEntry = CurrentModule.InLoadOrderLinks.Flink;
	}
	*lpcbNeeded = Count * sizeof(HMODULE);

	return TRUE;
}

static int match_ext(const WCHAR* ptr, size_t len)
{
	const WCHAR* const *e;
	size_t      l;

	for (e = ext; *e; e++)
	{
		l = lstrlenW(*e);
		if (l >= len) return 0;
		if (wcsnicmp(&ptr[len - l], *e, l)) continue;
		return l;
	}
	return 0;
}

static const WCHAR* get_filename(const WCHAR* name, const WCHAR* endptr)
{
	const WCHAR*        ptr;

	if (!endptr) endptr = name + lstrlenW(name);
	for (ptr = endptr - 1; ptr >= name; ptr--)
	{
		if (*ptr == '/' || *ptr == '\\') break;
	}
	return ++ptr;
}

static void module_fill_module(const WCHAR* in, WCHAR* out, size_t size)
{
	const WCHAR *ptr, *endptr;
	size_t      len, l;

	ptr = get_filename(in, endptr = in + lstrlenW(in));
	len = min(endptr - ptr, size - 1);
	memcpy(out, ptr, len * sizeof(WCHAR));
	out[len] = '\0';
	if (len > 4 && (l = match_ext(out, len)))
		out[len - l] = '\0';
	else
	{
		if (len > 3 && !wcsicmp(&out[len - 3], S_DotSoW) &&
			(l = match_ext(out, len - 3)))
			lstrcpyW(&out[len - l - 3], S_ElfW);
	}
	while ((*out = towlower(*out))) out++;
}

BOOL WINAPI myGetModuleInformation(HANDLE hProcess,HMODULE hModule,LPMODULEINFO lpmodinfo,DWORD cb)
{
	MODULEINFO LocalInfo;
	LDR_DATA_TABLE_ENTRY1 Module;

	/* Check output size */
	if (cb < sizeof(MODULEINFO))
	{
		SetLastError(ERROR_INSUFFICIENT_BUFFER);
		return FALSE;
	}

	/* Get the matching module */
	if (!FindModule(hProcess, hModule, &Module))
	{
		return FALSE;
	}

	/* Get a local copy first, to check for valid pointer once */
	LocalInfo.lpBaseOfDll = hModule;
	LocalInfo.SizeOfImage = Module.SizeOfImage;
	LocalInfo.EntryPoint = Module.EntryPoint;

	/* Attempt to copy to output */
	memcpy(lpmodinfo, &LocalInfo, sizeof(LocalInfo));

	return TRUE;
}

DWORD WINAPI myGetModuleBaseNameW(HANDLE hProcess,HMODULE hModule,LPWSTR lpBaseName,DWORD nSize)
{
	DWORD Len;
	LDR_DATA_TABLE_ENTRY1 Module;

	/* Get the matching module */
	if (!FindModule(hProcess, hModule, &Module))
	{
		return 0;
	}

	/* Get the maximum len we have/can write in given size */
	Len = Module.BaseDllName.Length + sizeof(UNICODE_NULL);
	if (nSize * sizeof(WCHAR) < Len)
	{
		Len = nSize * sizeof(WCHAR);
	}

	//read_process_memory(GetProcessId(hProcess)

	/* Read string */
	if (!read_process_memory(GetProcessId(hProcess), (UINT64)(&Module.BaseDllName)->Buffer, lpBaseName, Len))
	{
		return 0;
	}

	/* If we are at the end of the string, prepare to override to nullify string */
	if (Len == Module.BaseDllName.Length + sizeof(UNICODE_NULL))
	{
		Len -= sizeof(UNICODE_NULL);
	}

	/* Nullify at the end if needed */
	if (Len >= nSize * sizeof(WCHAR))
	{
		if (nSize)
		{
			ASSERT(nSize >= sizeof(UNICODE_NULL));
			lpBaseName[nSize - 1] = UNICODE_NULL;
		}
	}
	/* Otherwise, nullify at last written char */
	else
	{
		ASSERT(Len + sizeof(UNICODE_NULL) <= nSize * sizeof(WCHAR));
		lpBaseName[Len / sizeof(WCHAR)] = UNICODE_NULL;
	}

	return Len / sizeof(WCHAR);
}

BOOL WINAPI my_EnumerateLoadedModulesW64(HANDLE hProcess,PENUMLOADED_MODULES_CALLBACKW64 EnumLoadedModulesCallback,PVOID UserContext)
{
	HMODULE*    hMods;
	WCHAR       baseW[256], modW[256];
	DWORD       i, sz;
	MODULEINFO  mi;

	hMods = (HMODULE*)HeapAlloc(GetProcessHeap(), 0, 256 * sizeof(hMods[0]));
	if (!hMods) return FALSE;

	if (!my_EnumProcessModules(hProcess, hMods, 256 * sizeof(hMods[0]), &sz))
	{
		/* hProcess should also be a valid process handle !! */
		printf("If this happens, bump the number in mod\n");
		HeapFree(GetProcessHeap(), 0, hMods);
		return FALSE;
	}
	sz /= sizeof(HMODULE);
	for (i = 0; i < sz; i++)
	{
		if (!myGetModuleInformation(hProcess, hMods[i], &mi, sizeof(mi)) ||
			!myGetModuleBaseNameW(hProcess, hMods[i], baseW, ARRAY_SIZE(baseW)))
			continue;
		module_fill_module(baseW, modW, ARRAY_SIZE(modW));
		EnumLoadedModulesCallback(modW, (DWORD_PTR)mi.lpBaseOfDll, mi.SizeOfImage,
			UserContext);
	}
	HeapFree(GetProcessHeap(), 0, hMods);

	return sz != 0 && i == sz;
}

void fetch_modules_info(struct dump_context* dc)
{
	//EnumerateLoadedModulesW64(dc->handle, fetch_pe_module_info_cb, dc);
	my_EnumerateLoadedModulesW64(dc->handle, fetch_pe_module_info_cb, dc);
}

BOOL MiniDumpWriteDumpA(HANDLE hProcess, DWORD pid, HANDLE hFile)
{
	static const MINIDUMP_DIRECTORY emptyDir = { UnusedStream, {0, 0} };
	MINIDUMP_HEADER     mdHead;
	MINIDUMP_DIRECTORY  mdDir;
	DWORD               i, nStreams, idx_stream;
	struct dump_context dc;
	//BOOL                sym_initialized = FALSE;
	BOOL                sym_initialized = TRUE;

	const DWORD Flags = MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithUnloadedModules;

	MINIDUMP_TYPE DumpType = (MINIDUMP_TYPE)Flags;

	//if (!(sym_initialized = SymInitializeW(hProcess, NULL, TRUE)))
	//{
	//	DWORD err = GetLastError();
	//	return FALSE;
	//}

	dc.hFile = hFile;
	dc.pid = pid;
	dc.handle = hProcess;
	dc.modules = NULL;
	dc.num_modules = 0;
	dc.alloc_modules = 0;
	dc.threads = NULL;
	dc.num_threads = 0;
	dc.type = DumpType;
	dc.mem = NULL;
	dc.num_mem = 0;
	dc.alloc_mem = 0;
	dc.mem64 = NULL;
	dc.num_mem64 = 0;
	dc.alloc_mem64 = 0;
	dc.rva = 0;

	if (!fetch_process_info(&dc))
		return FALSE;

	fetch_modules_info(&dc);

	nStreams = 3;
	nStreams = (nStreams + 3) & ~3;

	// Write Header
	mdHead.Signature = MINIDUMP_SIGNATURE;
	mdHead.Version = MINIDUMP_VERSION;
	mdHead.NumberOfStreams = nStreams;
	mdHead.CheckSum = 0;
	mdHead.StreamDirectoryRva = sizeof(mdHead);
	//mdHead.TimeDateStamp = time(NULL);
	mdHead.Flags = DumpType;
	append(&dc, &mdHead, sizeof(mdHead));

	// Write Stream Directories 
	dc.rva += nStreams * sizeof(mdDir);
	idx_stream = 0;

	// Write Data Stream Directories 
	//

	// Must be first in MiniDump
	mdDir.StreamType = SystemInfoStream;
	mdDir.Location.Rva = dc.rva;
	mdDir.Location.DataSize = dump_system_info(&dc);
	writeat(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir), &mdDir, sizeof(mdDir));

	mdDir.StreamType = ModuleListStream;
	mdDir.Location.Rva = dc.rva;
	mdDir.Location.DataSize = dump_modules(&dc, FALSE);
	writeat(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir), &mdDir, sizeof(mdDir));

	fetch_memory64_info(&dc);

	mdDir.StreamType = Memory64ListStream;
	mdDir.Location.Rva = dc.rva;
	mdDir.Location.DataSize = dump_memory64_info(&dc);
	writeat(&dc, mdHead.StreamDirectoryRva + idx_stream++ * sizeof(mdDir), &mdDir, sizeof(mdDir));

	// fill the remaining directory entries with 0's (unused stream types)
	// NOTE: this should always come last in the dump!
	for (i = idx_stream; i < nStreams; i++)
		writeat(&dc, mdHead.StreamDirectoryRva + i * sizeof(emptyDir), &emptyDir, sizeof(emptyDir));

	if (sym_initialized)
		SymCleanup(hProcess);

	HeapFree(GetProcessHeap(), 0, dc.mem);
	HeapFree(GetProcessHeap(), 0, dc.mem64);
	HeapFree(GetProcessHeap(), 0, dc.modules);
	HeapFree(GetProcessHeap(), 0, dc.threads);

	return TRUE;
}

HANDLE GetProcessHandle(DWORD dwPid)
{
	HANDLE hProcess = NULL;
	//hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, dwPid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);
	if (hProcess == NULL)
		printf("Open Process %d\n", GetLastError());
		return NULL;

	return hProcess;
}

void EnableDebugPriv()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	BOOL status = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken);
	if (status == FALSE)
	{
		printf("Failed to open process token.\n");
		return;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LPCWSTR lpwPriv = L"SeDebugPrivilege";
	if (!LookupPrivilegeValueW(NULL, lpwPriv, &tkp.Privileges[0].Luid))
	{
		CloseHandle(hToken);
		return;
	}

	status = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if (status != STATUS_SUCCESS)
		printf("Failed to adjust process token.\n");

	CloseHandle(hToken);
}

int main(int argc, char* argv[])
{

	char drv_path[MAX_PATH] = { 0 };

    char tempPath[MAX_PATH] = { 0 };
    char curDirPath[MAX_PATH] = { 0 };
    if (!GetTempPathA(MAX_PATH, tempPath))
    {
        printf("Can not get tmp path...\n");
        return 0;
    }
    if (!GetCurrentDirectoryA(MAX_PATH, curDirPath))
    {
        printf("Can not get cur path...\n");
        return 0;
    }
    printf("tmp path: %s\n", tempPath);
    printf("cur dir path: %s\n", curDirPath);
    char raw_drv_path[MAX_PATH] = { 0 };
    sprintf_s(drv_path, "%s\\%s", tempPath, "mhyprot2.Sys");
    sprintf_s(raw_drv_path, "%s\\%s", curDirPath, "mhyprot2.Sys");

    printf("drv path: %s\n", drv_path);
    printf("raw path: %s\n", raw_drv_path);
    CopyFileA(raw_drv_path, drv_path, true);
    pdrvCtl1 = new MhyDrvIO(drv_path);
	int    pid;
	char* output_file;

	if (argc != 3)
		return 1;
	EnableDebugPriv();
	pid = atoi(argv[1]);
	output_file = argv[2];
	printf("id %d\n", pid);
	HANDLE hProc = GetProcessHandle(pid);
	if (!hProc)
	{
		
		printf("Failed to open process.\n");
		return 0;
	}
	
	const DWORD Flags = MiniDumpWithFullMemory |
		MiniDumpWithFullMemoryInfo |
		MiniDumpWithHandleData |
		MiniDumpWithUnloadedModules |
		MiniDumpWithThreadInfo;

	HANDLE hFile = CreateFileA(output_file, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hFile)
	{
		printf("Failed to write dump: Invalid dump file path.\n");
		return 0;
	}

	BOOL Result = MiniDumpWriteDumpA(hProc, GetProcessId(hProc), hFile);
    delete pdrvCtl1;
}