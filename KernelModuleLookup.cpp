#include <windows.h>

#include "KernelModuleLookup.h"

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 0xB
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;
    ULONG Unknow3;
    ULONG Unknow4;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );

DWORD64 LookupDriverBaseAddr(LPCSTR DriverName)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL) return 0;

    ULONG NeedSize, i, ModuleCount, BufferSize = 0x5000;
    PVOID pBuffer = NULL;
    PCHAR pDrvName = NULL;
    NTSTATUS Result;
    PSYSTEM_MODULE_INFORMATION pSystemModuleInformation;
    do
    {
        pBuffer = calloc(1, BufferSize);
        if (pBuffer == NULL) return 0;

        Result = NtQuerySystemInformation(SystemModuleInformation, pBuffer, BufferSize, &NeedSize);
        if (Result == 0xC0000004L)
        {
            free(pBuffer);
            pBuffer = NULL;
            BufferSize *= 2;
        }
        else if (Result < 0)
        {
            free(pBuffer);
            return 0;
        }
    } while (Result == 0xC0000004L);

    if (pBuffer == NULL) return 0;
    pSystemModuleInformation = (PSYSTEM_MODULE_INFORMATION)pBuffer;
    ModuleCount = pSystemModuleInformation->Count;

    for (i = 0; i < ModuleCount; i++)
    {
        if ((ULONG64)(pSystemModuleInformation->Module[i].Base) > (ULONG64)0x8000000000000000)
        {
            pDrvName = pSystemModuleInformation->Module[i].ImageName + pSystemModuleInformation->Module[i].ModuleNameOffset;
            if (_stricmp(pDrvName, DriverName) == 0)
            {
                return (DWORD64)pSystemModuleInformation->Module[i].Base;
            }
        }
    }

    free(pBuffer);
    return 0;
}