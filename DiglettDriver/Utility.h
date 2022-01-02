#pragma once
#include <ntifs.h>
#include "Driver.h"

typedef unsigned char uint8_t;
typedef unsigned long long uint64_t;

//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

#define PAGE_OFFSET_SIZE 12
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

class Utility
{
public:
	static NTSTATUS GetProcessBaseAddress(_In_ UINT32 pid, _Out_ PVOID* procBase);
	static DWORD GetUserDirectoryTableBaseOffset();
	static ULONG_PTR GetProcessCr3(PEPROCESS pProcess);
	static ULONG_PTR GetKernelDirBase();
	static NTSTATUS ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read);
	static NTSTATUS WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written);
	static NTSTATUS ReadPhysicalAddress(uint64_t TargetAddress, uint64_t lpBuffer, SIZE_T Size, SIZE_T* BytesRead);
	static NTSTATUS WritePhysicalAddress(uint64_t TargetAddress, uint64_t lpBuffer, SIZE_T Size, SIZE_T* BytesWritten);
	static uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress);
	static NTSTATUS ReadProcessMemory(UINT32 pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read);
	static NTSTATUS WriteProcessMemory(UINT32 pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written);
	static NTSTATUS ImportWinPrimitives(_Out_ GenericFuncPtr pWinPrims[], _In_ wchar_t* names[]);
	static BOOL GetUserModBase(PCHAR modName, UINT64 pid, PUINT64 outBase, PUINT64 outSize);
	static NTSTATUS Utility::Sleep(_In_ LONG milliseconds);

private:
	PRTL_PROCESS_MODULES outProcMods = NULL;
	DevCtrlPtr origDeviceControl = NULL;
	volatile bool runThread = true;
	uintptr_t kernBase = NULL;
};
