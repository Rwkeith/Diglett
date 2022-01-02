#pragma once
#include "Utility.h"
#include <windef.h>
#include <ntstrsafe.h>
#include <intrin.h>


NTSTATUS Utility::GetProcessBaseAddress(_In_ UINT32 pid, _Out_ PVOID* procBase)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0)
		return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS)
		return NtRet;

	*procBase = PsGetProcessSectionBaseAddress(pProcess);
	ObDereferenceObject(pProcess);
}

DWORD Utility::GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);

	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR Utility::GetProcessCr3(PEPROCESS pProcess)
{
	PUCHAR process = (PUCHAR)pProcess;
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	if (process_dirbase == 0)
	{
		DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return process_userdirbase;
	}
	return process_dirbase;
}

ULONG_PTR Utility::GetKernelDirBase()
{
	PUCHAR process = (PUCHAR)PsGetCurrentProcess();
	ULONG_PTR dirTableBase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	return dirTableBase;
}

NTSTATUS Utility::ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress(paddress, (uint64_t)buffer, size, read);
}

NTSTATUS Utility::WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return WritePhysicalAddress(paddress, (uint64_t)buffer, size, written);
}

NTSTATUS Utility::ReadPhysicalAddress(uint64_t TargetAddress, uint64_t lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = (UINT64)TargetAddress;
	return MmCopyMemory((PVOID)lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS Utility::WritePhysicalAddress(uint64_t TargetAddress, uint64_t lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!TargetAddress)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = (UINT64)TargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, (PVOID)lpBuffer, Size);

	*BytesWritten = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}

uint64_t Utility::TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress) {
	directoryTableBase &= ~0xf;

	uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
	uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
	uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
	uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	uint64_t pdpe = 0;
	ReadPhysicalAddress(directoryTableBase + 8 * pdp, (uint64_t)&pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	uint64_t pde = 0;
	ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, (uint64_t)&pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	uint64_t pteAddr = 0;
	ReadPhysicalAddress((pde & PMASK) + 8 * pt, (uint64_t)&pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, (uint64_t)&virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

NTSTATUS Utility::ReadProcessMemory(UINT32 pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{

		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		NtRet = ReadPhysicalAddress(CurPhysAddr, ((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesRead == 0) break;
	}

	*read = CurOffset;
	return NtRet;
}

NTSTATUS Utility::WriteProcessMemory(UINT32 pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		NtRet = WritePhysicalAddress(CurPhysAddr, ((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesWritten == 0) break;
	}

	*written = CurOffset;
	return NtRet;
}

/// <summary>
/// Dynamic importing via a documented method
/// </summary>
/// <param name="pWinPrims">Array that holds WinPrimitive pointers</param>
/// <param name="names">names of routines to import</param>
/// <returns></returns>
NTSTATUS Utility::ImportWinPrimitives(_Out_ GenericFuncPtr(pWinPrims[]), _In_ wchar_t* names[])
{
	LogInfo("Importing windows primitives\n");

	UNICODE_STRING uniNames[WINAPI_IMPORT_COUNT];

	for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
	{
		RtlInitUnicodeString(&uniNames[i], names[i]);
	}

	for (size_t i = 0; i < WINAPI_IMPORT_COUNT; i++)
	{
		pWinPrims[i] = (GenericFuncPtr)MmGetSystemRoutineAddress(&uniNames[i]);
		if (pWinPrims[i] == NULL)
		{
			LogError("Failed to import %ls\n", uniNames[i].Buffer);
			return STATUS_UNSUCCESSFUL;
		}
		else
		{
			LogInfo("Succesfully imported %ls at %p\n", uniNames[i].Buffer, pWinPrims[i]);
		}
	}
	return STATUS_SUCCESS;
}

NTSTATUS Utility::Sleep(_In_ LONG milliseconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -(10ll * milliseconds);

	return KeDelayExecutionThread(KernelMode, FALSE, &interval);
}


BOOL Utility::GetUserModBase(PCHAR modName, UINT64 pid, PUINT64 outBase, PUINT64 outSize)
{
	LogInfo("Outputting modules for PID: %llu", pid);
	PEPROCESS process = NULL;
	PsLookupProcessByProcessId((HANDLE)pid, &process);
	if (!process)
	{
		LogInfo("Failed to retrieve EPROCESS struct");
		return false;
	}
	LogInfo("\nPEPROCESS: 0x%p", process);
		
	// virtual address is in context of that process

	const auto peb = PsGetProcessPeb(process);
	LogInfo("\nPEB: 0x%p", peb);

	// Change cr3 so that translation in the CPU as we need to access virtual address from game

	const auto dirBase = GetProcessCr3(process);
	LogInfo("\nDirectory Base: 0x%p", (PVOID)dirBase);

	// Loop through peb->ldr->InMemoryOrderModuleList
	UINT64 ldrAddr = NULL;
	SIZE_T read = 0;

	// ldr offset on 21H1 0x18
	NTSTATUS status = ReadVirtual(dirBase, ((UINT64)peb + 0x18), (uint8_t*)&ldrAddr, 0x8, &read);
	if (!NT_SUCCESS(status))
	{
		LogInfo("Failed to read Peb->Ldr");
		return false;
	}
	LogInfo("\nPeb->Ldr: 0x%p", (PVOID)ldrAddr);

	PLIST_ENTRY inMemoryOrderModuleList;
	read = 0;
	// InMemoryOrderModList offset 0x20 on 21H1
	status = ReadVirtual(dirBase, (uint64_t)(ldrAddr + 0x20), (uint8_t*)&inMemoryOrderModuleList, 0x8, &read);
	if (!NT_SUCCESS(status))
	{
		LogInfo("Failed to read Peb->Ldr->InMemoryOrderModuleList");
		return false;
	}

	LogInfo("\nPeb->Ldr->InMemoryOrderModuleList.Flink: 0x%p", inMemoryOrderModuleList);


	const auto calling_process_cr3 = __readcr3();
	const auto games_cr3 = GetProcessCr3(process); //(UINT64)((BYTE*)process + 0x28);

	//PLDR_DATA_TABLE_ENTRY
	//LogInfo("\nPeb->Ldr->InMemoryOrderModuleList.Flink->FullDllName: %wZ", ((PLDR_DATA_TABLE_ENTRY)inMemoryOrderModuleList->Flink)->FullDllName);

	//PLIST_ENTRY head = inMemoryOrderModuleList;//(PLIST_ENTRY)(((UINT64) *((PVOID*)((UINT64)peb + 0xC))) + 0x14);
	PLIST_ENTRY head = (PLIST_ENTRY)(ldrAddr + 0x20);
	PLIST_ENTRY next;

	//LogInfo("head: %p", head);
	//LogInfo("head->Flink: %p", head->Flink);
	PLDR_DATA_TABLE_ENTRY entry;
	int i = 0;
//	KIRQL oldIrql = KeGetCurrentIrql();
	// IRQL_NOT_LESS_OR_EQUAL
	
//	__writecr8(0xF);
	//auto oldIrql = KeRaiseIrqlToDpcLevel();
	//_disable();
//	LogInfo("oldIrql: %d", oldIrql);
	
	//__writecr3(games_cr3);
	
	//LogInfo("head->Flink: %p", head->Flink);
	//next = head->Flink;
	//entry = (PLDR_DATA_TABLE_ENTRY)next;
	//LogInfo("entry->FullDllName: %wZ", &(entry->FullDllName));

	//next = next->Flink;
	//entry = (PLDR_DATA_TABLE_ENTRY)next;
	//LogInfo("entry->FullDllName: %wZ", &(entry->FullDllName));

	//LogInfo("head->Flink: %wZ", &(((PLDR_DATA_TABLE_ENTRY)head)->FullDllName));
	//__writecr3(games_cr3);
	KAPC_STATE ApcState;

	KeStackAttachProcess(process, &ApcState);

	for (next = head->Flink; next != head; next = next->Flink) {
		// Check if BaseDllName matches our target
		entry = (PLDR_DATA_TABLE_ENTRY)next;
		LogInfo("entry->FullDllName: %wZ", &(entry->FullDllName));
		LogInfo("entry->DllBase: %p", &(entry->DllBase));
	}

	//const auto base = (uintptr_t)cur_entry->DllBase;
	//const auto size = (size_t)cur_entry->SizeOfImage;

	// Detach, we are now back in the address space of our calling process
	
	KeUnstackDetachProcess(&ApcState);
	
	//LogInfo("Thread dies? 1");
	//__writecr3(calling_process_cr3);
	//_enable();
	//KeLowerIrql(oldIrql);
//	__writecr8(oldIrql);
	ObDereferenceObject(process);
	//*outBase = base;
	//*outSize = size;
	return true;
}
