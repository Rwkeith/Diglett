#pragma once
#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include "PEHdr.h"
//#pragma comment(lib, "ntoskrnl.lib")
#pragma warning (disable : 4201)


//#define DEBUG

// @jk2
#ifdef DEBUG
#define Log(format, ...) KdPrint(("[DIGLETT] " format "\n", __VA_ARGS__))
#define LogInfo(format, ...) KdPrint(("[DIGLETT] [INFO] " format "\n", __VA_ARGS__))
#define LogError(format, ...) KdPrint(("[DIGLETT] [ERROR] " format "\n", __VA_ARGS__))

#else
#define Log(format, ...) 
#define LogInfo(format, ...) 
#define LogError(format, ...)

#endif

#define MAX_NAME_LEN 25
#define WINAPI_IMPORT_COUNT 1
#define PAGE_SIZE 0x1000
#define PML4_OFFSET_MASK 0b00000000 11111111 00000000 00000000 00000000 00000000 00000000 00000000

#define ZW_QUERY_INFO 0
#define SYSTEM_MODULE_INFORMATION 0x0B

typedef unsigned long long uint64_t;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

extern "C"
{
	__declspec(dllimport) NTSTATUS ZwQuerySystemInformation(
		ULONG InfoClass,
		PVOID Buffer,
		ULONG Length,
		PULONG ReturnLength
	);

	NTKERNELAPI PVOID NTAPI RtlFindExportsRoutineByName(
		_In_ PVOID ImageBase,
		_In_ PCCH RoutineName
	);

	NTKERNELAPI PPEB PsGetProcessPeb(
		_In_ PEPROCESS Process
	);

	NTSTATUS NTAPI MmCopyVirtualMemory(
		PEPROCESS SourceProcess,
		PVOID SourceAddress,
		PEPROCESS TargetProcess,
		PVOID TargetAddress,
		SIZE_T BufferSize,
		KPROCESSOR_MODE PreviousMode,
		PSIZE_T ReturnSize
	);

	typedef void (*GenericFuncPtr)();
	typedef NTSTATUS(*ZwQuerySysInfoPtr)(ULONG, PVOID, ULONG, PULONG);
}

NTSTATUS DeviceControl(PDEVICE_OBJECT, _Inout_ PIRP Irp);
NTSTATUS EnumKernelModuleInfo(_In_ ZwQuerySysInfoPtr ZwQuerySysInfo);
NTSTATUS ImportWinPrimitives(_Out_ GenericFuncPtr pWinPrims[], _In_ wchar_t* names[]);
PLOAD_IMAGE_NOTIFY_ROUTINE ImageNotifyRoutine(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcID, _In_ PIMAGE_INFO ImageInfo);
