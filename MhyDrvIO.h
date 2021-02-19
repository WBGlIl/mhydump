#pragma once
class MhyDrvIO
{
private:
	struct MHY_IO_CTL
	{
		const DWORD InitDrvSeedArray = 0x80034000;
		const DWORD ReadKernelMem = 0x83064000;
		const DWORD RWProcMem = 0x81074000;
	} io_ctls;
	typedef struct
	{
		DWORD d1;
		DWORD d2;
		DWORD64 q1;
	} InitSeedData, * PInitSeedData;
	typedef struct
	{
		union _HeadData
		{
			DWORD result;
			DWORD64 KernelAddr;
		} HeadData;
		ULONG Size;
	} ReadKernelData, * PReadKernelData;
	typedef struct
	{
		DWORD64 randomKey;
		DWORD Action;
		DWORD Unknown0;
		DWORD PID;
		DWORD Unknown1;
		DWORD64 DestAddr;
		DWORD64 SrcAddr;
		ULONG Size;
		ULONG Unknown2;
	} ReadWriteProcData, * PReadWriteProcData;
	const char* drvFileName = NULL;
	const char* ioFileName = "\\\\?\\\\mhyprot2";
	const char* serviceName = "mhyprot2";
	const char* drvSysName = "mhyprot2.Sys";
	HANDLE hDevice = NULL;
	DWORD64 seedmap[312] = { 0 };

	bool InitDrv();
	void UnloadDrv();
	bool ConnectDrv();
	bool SetupDrv();
	DWORD64 GetKey(DWORD64 seed);
	void CryptData(PVOID data, DWORD size);
	bool IoControl(DWORD ControlCode, PVOID Data, DWORD Size);
	bool InitSeedArray();
public:
	MhyDrvIO(const char* drvFileNameIn)
	{
		if (!drvFileNameIn) throw "drvFileName can not be null";
		this->drvFileName = drvFileNameIn;
		this->InitDrv();
	}
	~MhyDrvIO()
	{
		this->UnloadDrv();
	}
	bool ReadKernelMem(DWORD64 addr, DWORD size, void* outBuff);
	bool ReadProcMem(DWORD pid, DWORD64 addr, DWORD size, void* outBuff);
	bool WriteProcMem(DWORD pid, DWORD64 addr, DWORD size, void* inBuff);
};

