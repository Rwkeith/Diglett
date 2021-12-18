#pragma once
#include "Driver.h"
#include "Common.h"

// for register macros
//#include <intrin.h>
//#include "asmstubs.h"

PRTL_PROCESS_MODULES outProcMods = NULL;
DevCtrlPtr origDeviceControl = NULL;
volatile bool runThread = true;
uintptr_t kernBase = NULL;

bool IsValidPEHeader(_In_ const uintptr_t pHead)
{
    // ideally should parse the PT so this can't be IAT spoofed
    if (!MmIsAddressValid((PVOID)pHead))
    {
#ifdef VERBOSE_LOG
        LogError("Was unable to read page @ 0x%p", (PVOID)pHead);
#endif
        return false;
    }

    if (!pHead)
    {
        LogInfo("pHead is null @ 0x%p", (PVOID)pHead);
        return false;
    }

    if (reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_magic != E_MAGIC)
    {
        //LogInfo("pHead is != 0x%02x @ %p", E_MAGIC, (PVOID)pHead);
        return false;
    }

    const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(pHead + reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_lfanew);

    // avoid reading a page not paged in
    if (reinterpret_cast<PIMAGE_DOS_HEADER>(pHead)->e_lfanew > 0x1000)
    {
        LogInfo("pHead->e_lfanew > 0x1000 , doesn't seem valid @ 0x%p", (PVOID)pHead);
        return false;
    }

    if (ntHeader->Signature != NT_HDR_SIG)
    {
        LogInfo("ntHeader->Signature != 0x%02x @ 0x%p", NT_HDR_SIG, (PVOID)pHead);
        return false;
    }

    LogInfo("Found valid PE header @ 0x%p", (PVOID)pHead);
    return true;
}


// @ Barakat , GS Register, reverse page walk until MZ header of ntos
// https://gist.github.com/Barakat/34e9924217ed81fd78c9c92d746ec9c6
// Lands above nt module, but can page fault! Tweak to check PTE's instead of using MmIsAddressValid.  Refer to:  https://www.unknowncheats.me/forum/anti-cheat-bypass/437451-whats-proper-write-read-physical-memory.html
uintptr_t GetNtoskrnlBaseAddress()
{
#pragma pack(push, 1)
    typedef struct
    {
        UCHAR Padding[4];
        PVOID InterruptServiceRoutine;
    } IDT_ENTRY;
#pragma pack(pop)

    // Find the address of IdtBase using gs register.
    const auto idt_base = reinterpret_cast<IDT_ENTRY*>(__readgsqword(0x38));

    // Find the address of the first (or any) interrupt service routine.
    const auto first_isr_address = idt_base[0].InterruptServiceRoutine;

    // Align the address on page boundary.
    auto pageInNtoskrnl = reinterpret_cast<uintptr_t>(first_isr_address) & ~static_cast<uintptr_t>(0xfff);

    // Traverse pages backward until we find the PE signature (MZ) of ntoskrnl.exe in the beginning of some page.
    while (!IsValidPEHeader(pageInNtoskrnl))
    {
        pageInNtoskrnl -= 0x1000;
    }

    // Now we have the base address of ntoskrnl.exe
    return pageInNtoskrnl;
}


extern "C" NTSTATUS DriverEntry()
{
    Log("DriverEntry() Starting Diglett!\n");

    //LogInfo("Setting LoadImageNotify routine\n");
    //PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageNotifyRoutine);
    
    // Diglett is not legit, he doesn't create a device object :(

    //wchar_t* apiNames[WINAPI_IMPORT_COUNT] = { L"ZwQuerySystemInformation" };
    ////PVOID pWinPrims[WINAPI_IMPORT_COUNT];
    //GenericFuncPtr(pWinPrims[WINAPI_IMPORT_COUNT]);
    //NTSTATUS status = ImportWinPrimitives(pWinPrims, apiNames);
    //if (!NT_SUCCESS(status))
    //{
    //    LogError("Importing windows primitives failed.  Aborting task\n");
    //    return STATUS_SUCCESS;
    //}

    //EnumKernelModuleInfo((ZwQuerySysInfoPtr)pWinPrims[ZW_QUERY_INFO]);
    //SetHk_tcpip(true);

    kernBase = GetNtoskrnlBaseAddress();

    HANDLE threadHandle;
    PsCreateSystemThread(&threadHandle, GENERIC_ALL, 0, 0, 0, MainThread, 0);
    ZwClose(threadHandle);
    LogInfo("~DriverEntry()\n");
    return STATUS_SUCCESS;
}

extern "C" void MainThread(PVOID StartContext)
{
    LogInfo("Allocated using MDL method with mapper");

    int increment = 0;
    LogInfo("runThread == True, looping thread\n");
    HANDLE ourThread = PsGetCurrentThreadId();
    LogInfo("Our thread id:  %llu\n", (unsigned long long)ourThread);
    KIRQL currIrql = KeGetCurrentIrql();
    LogInfo("Current Irql before KeDelayExecutionThread: %d", currIrql);
    auto cpuIndex = KeGetCurrentProcessorNumber();
    LogInfo("Running on CPU: %lu", cpuIndex);
    
    PKTHREAD thisThread = (PKTHREAD)__readgsqword(0x188);

    LogInfo("Hiding system thread:");
    thisThread = reinterpret_cast<PKTHREAD>(KeGetCurrentThread());
    LogInfo("\t\t\tKTHREAD->SystemThread = %lu", thisThread->SystemThread);
    thisThread->SystemThread = 0;
    LogInfo("\t\t\tKTHREAD->SystemThread = %lu", thisThread->SystemThread);

    LogInfo("Spoofing thread entry point:");
    _ETHREAD* myThread = reinterpret_cast<_ETHREAD*>(thisThread);
    LogInfo("\t\t\t_ETHREAD->StartAddress = %p", myThread->StartAddress);
    uintptr_t inNtosText = kernBase + 0x3000;
    myThread->StartAddress = (PVOID)inNtosText;
    LogInfo("\t\t\t_ETHREAD->StartAddress = %p", myThread->StartAddress);
    LogInfo("\t\t\t_ETHREAD->Win32StartAddress = %p", myThread->Win32StartAddress);
    myThread->Win32StartAddress = (PVOID)inNtosText;
    LogInfo("\t\t\t_ETHREAD->Win32StartAddress = %p", myThread->Win32StartAddress);

    while (runThread)
    {
        LARGE_INTEGER li;
        //li.QuadPart = -10000; // 1 ms delay
        li.QuadPart = -10000000;
        KeDelayExecutionThread(KernelMode, FALSE, &li);
    }
    LogInfo("runThread == False, exiting thread\n");
}

/// <summary>
/// Dynamic importing via a documented method
/// </summary>
/// <param name="pWinPrims">Array that holds WinPrimitive pointers</param>
/// <param name="names">names of routines to import</param>
/// <returns></returns>
NTSTATUS ImportWinPrimitives(_Out_ GenericFuncPtr(pWinPrims[]), _In_ wchar_t* names[])
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

// Communication method via hook in legit driver control handler
NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT tcpipDevObj, PIRP Irp)
{
    LogInfo("Hooked routine executed!\n");

    // In the context of tcpip thread
    auto stack = IoGetCurrentIrpStackLocation(Irp);
    auto status = STATUS_SUCCESS;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_ECHO_REQUEST: {
        LogInfo("IOCTL_ECHO_REQUEST received!!\n");
        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ECHO_DATA))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        auto data = (PECHO_DATA)stack->Parameters.DeviceIoControl.Type3InputBuffer;

        if (data == nullptr)
        {
            status = STATUS_SUCCESS; // <- TEST
            //status = STATUS_INVALID_PARAMETER;
            break;
        }

        LogInfo("Echo request output: %s\n", data->strEcho);
        Irp->IoStatus.Status = CUSTOM_STATUS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return CUSTOM_STATUS;
    }
    default:
        LogInfo("Unrecognized IoControlCode, forwarding to original DeviceControl.\n");
        return origDeviceControl(tcpipDevObj, Irp);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/* hook/unhook driver */
NTSTATUS SetHk_tcpip(_In_ BOOLEAN hook)
{
    LogInfo("Hooking tcpip device control...\n");
    UNICODE_STRING drvName;
    UNICODE_STRING newDrvName;
    //PDRIVER_OBJECT tcpipDrvObj;
    DRIVER_OBJECT myDummyDriver;
    PDEVICE_OBJECT tcpipDevice;
    PDRIVER_OBJECT tcpipDriver;
    NTSTATUS status;
    PDRIVER_OBJECT dummyDriver;
    //HANDLE fileHandle;
    //UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\\\Windows\\System32\\drivers\\tcpip.sys");
    //OBJECT_ATTRIBUTES objAttr;
    //IO_STATUS_BLOCK ioStatusBlock;

    //RtlInitUnicodeString(&drvName, L"\\Driver\\tcpip");
    RtlInitUnicodeString(&drvName, L"\\Driver\\tcpip");
    RtlInitUnicodeString(&newDrvName, L"\\Driver\\newDrvName");
    //EXISTING
    //InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    //status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    //if (status != STATUS_SUCCESS)
    //{
    //    LogError("ZwCreateFile failed status:  0x%08x\n", status);
    //    return status;
    //}

    //tcpipDevice = IoGetRelatedDeviceObject();

    // Create our own dummy driver
    // name is spoofed?
    IoCreateDriver(&newDrvName, (PDRIVER_INITIALIZE)DummyDrv_Init);
    //status = ObReferenceObjectByName(&newDrvName, OBJ_CASE_INSENSITIVE, NULL, 0,
    //    *IoDriverObjectType, KernelMode, NULL, (PVOID*)&dummyDriver);


    return STATUS_SUCCESS;
}

NTSTATUS DummyDrv_Init(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    return STATUS_SUCCESS;
}

/*
* WIP to manually parse PTE entries
* 
void ShowPTEData(PVOID VirtAddress)
{
    UINT64 cr3 = __readcr3();
    KdPrint(("CR3: 0x%08x", cr3));
    
    // 47 : 39
    UINT64 PML4_ENTRY = cr3 + ((*(UINT64*)VirtAddress)&&);

}

bool IsValidPTE(PVOID VirtAddress)
{
    UINT64 cr3 = __readcr3();
    // Page-Map Level-4 Table (PML4) (Bits 47-39)
    UINT64 PML4_ENTRY = cr3 + ((*(UINT64*)VirtAddress) && )
    
}
*/

/// <summary>
/// Uses ZwQuerySysInfo to get legit module ranges
/// </summary>
/// <param name="ZwQuerySysInfo">pointer to ZwQuerySystemInformation</param>
/// <param name="outProcMods">pointer to struct with data out</param>
/// <returns>status</returns>
NTSTATUS EnumKernelModuleInfo(_In_ ZwQuerySysInfoPtr ZwQuerySysInfo) {
    ULONG size = NULL;
    outProcMods = NULL;

    // test our pointer
    NTSTATUS status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, 0, 0, &size);
    if (STATUS_INFO_LENGTH_MISMATCH == status) {
        LogError("ZwQuerySystemInformation test successed, status: %08x", status);
    }
    else
    {
        LogError("Unexpected value from ZwQuerySystemInformation, status: %08x", status);
        return status;
    }

    outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
    if (!outProcMods) {
        LogError("Insufficient memory in the free pool to satisfy the request");
        return STATUS_UNSUCCESSFUL;
    }

    if (!NT_SUCCESS(status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, outProcMods, size, 0))) {
        LogError("ZwQuerySystemInformation failed");
        ExFreePool(outProcMods);
        return status;
    }

    KdPrint(("Using ZwQuerySystemInformation with SYSTEM_MODULE_INFORMATION.  Modules->NumberOfModules = %lu\n", outProcMods->NumberOfModules));

    for (ULONG i = 0; i < outProcMods->NumberOfModules; i++)
    {
        LogInfo("Module[%d].FullPathName: %s\n", (int)i, (char*)outProcMods->Modules[i].FullPathName);
        LogInfo("Module[%d].ImageBase: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageBase);
        LogInfo("Module[%d].MappedBase: %p\n", (int)i, (char*)outProcMods->Modules[i].MappedBase);
        LogInfo("Module[%d].LoadCount: %p\n", (int)i, (char*)outProcMods->Modules[i].LoadCount);
        LogInfo("Module[%d].ImageSize: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageSize);
    }

    LogInfo("ZwQuerySystemInformation complete\n");
    ExFreePool(outProcMods);
    return STATUS_SUCCESS;
}

// TODO
//NTSTATUS EnumSysThreadInfo(_In_ ZwQuerySysInfoPtr ZwQuerySysInfo) {
//    ULONG size = NULL;
//    outProcMods = NULL;
//
//    // test our pointer
//    NTSTATUS status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, 0, 0, &size);
//    if (STATUS_INFO_LENGTH_MISMATCH == status) {
//        KdPrint(("[NOMAD] [INFO] ZwQuerySystemInformation test successed, status: %08x", status));
//    }
//    else
//    {
//        KdPrint(("[NOMAD] [ERROR] Unexpected value from ZwQuerySystemInformation, status: %08x", status));
//        return status;
//    }
//
//    outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
//    if (!outProcMods) {
//        KdPrint(("[NOMAD] [ERROR] Insufficient memory in the free pool to satisfy the request"));
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    if (!NT_SUCCESS(status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, outProcMods, size, 0))) {
//        KdPrint(("[NOMAD] [ERROR] ZwQuerySystemInformation failed"));
//        ExFreePool(outProcMods);
//        return status;
//    }
//
//    KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation with SYSTEM_MODULE_INFORMATION.  Modules->NumberOfModules = %lu\n", outProcMods->NumberOfModules));
//
//    for (ULONG i = 0; i < outProcMods->NumberOfModules; i++)
//    {
//        KdPrint(("[NOMAD] [INFO] Module[%d].FullPathName: %s\n", (int)i, (char*)outProcMods->Modules[i].FullPathName));
//        KdPrint(("[NOMAD] [INFO] Module[%d].ImageBase: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageBase));
//        KdPrint(("[NOMAD] [INFO] Module[%d].MappedBase: %p\n", (int)i, (char*)outProcMods->Modules[i].MappedBase));
//        KdPrint(("[NOMAD] [INFO] Module[%d].LoadCount: %p\n", (int)i, (char*)outProcMods->Modules[i].LoadCount));
//        KdPrint(("[NOMAD] [INFO] Module[%d].ImageSize: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageSize));
//
//        //char* fileName = (char*)(outProcMods->Modules[i].FullPathName + outProcMods->Modules[i].OffsetToFileName);
//        //KdPrint(("[NOMAD] [INFO] fileName == %s\n", fileName));
//        //char* ret = strstr((char*)Modules->Modules[i].FullPathName + outProcMods->Modules[i].OffsetToFileName, ModuleName);
//
//        //if (!ret)
//        //    continue;
//        //else {
//        //    KdPrint(("[NOMAD] [INFO] Found Requested Module %s\n", fileName));
//        //    *ModuleInfo = Modules->Modules[i];
//        //    break;
//    }
//
//    KdPrint(("[NOMAD][INFO] Using ZwQuerySystemInformation complete\n"));
//    //ExFreePool(Modules);
//    return STATUS_SUCCESS;
//}

PLOAD_IMAGE_NOTIFY_ROUTINE ImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcID, PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);
    UNREFERENCED_PARAMETER(ProcID);

    if (wcsstr(FullImageName->Buffer, L"\\EasyAntiCheat.sys"))
    {
        //KdPrint(("[NOMAD] [INFO] !  Dumping!\n"));
        //UINT64 base = (UINT64)ImageInfo->ImageBase;
        //DumpKernelModule("WinKernelProgDrv.sys");
    }

    return STATUS_SUCCESS;
}