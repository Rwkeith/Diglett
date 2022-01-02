#pragma once
#include "Utility.h"
#include "Driver.h"
#include "Common.h"

#ifdef LEGIT_DRIVER
    NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
#else
    extern "C" NTSTATUS DriverEntry()
#endif // LEGIT_DRIVER
{
#ifdef LEGIT_DRIVER
        UNREFERENCED_PARAMETER(RegistryPath);
        Log("DriverEntry() Starting Diglett as legit driver!");
        // map major function handlers
        //DriverObject->MajorFunction[IRP_MJ_CREATE] = Create;
        //DriverObject->MajorFunction[IRP_MJ_CLOSE] = Close;
        //DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
        DriverObject->DriverUnload = Unload;

        // Create a device object for the usermode application to use
        UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\Diglett");

        PDEVICE_OBJECT DeviceObject;
        NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

        // error check for successful driver object creation
        if (!NT_SUCCESS(status))
        {
            LogError("Failed to create device object (0x%08X)", status);
            return status;
        }

        // provide symbolic link to device object to make accessible to usermode
        UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Diglett");
        status = IoCreateSymbolicLink(&symLink, &devName);

        // error check for sym link creation
        if (!NT_SUCCESS(status))
        {
            LogError("Failed to create symbolic link (0x%08X)\n", status);
            IoDeleteDevice(DeviceObject);
            return status;
        }

        LogInfo("Driver initialized successfully");
#else
        Log("DriverEntry() Starting Diglett as manually mapped driver!\n");
#endif // LEGIT_DRIVER

    //kernBase = GetNtoskrnlBaseAddress();

    UINT64 outBase = 0;
    UINT64 outSize = 0;
    Utility::GetUserModBase("unused.dll", 3712, &outBase, &outSize);

    //HANDLE threadHandle;
    //PsCreateSystemThread(&threadHandle, GENERIC_ALL, 0, 0, 0, MainThread, 0);
    //ZwClose(threadHandle);
    LogInfo("~DriverEntry()");
    return STATUS_SUCCESS;
}

#ifdef LEGIT_DRIVER
    void Unload(_In_ PDRIVER_OBJECT DriverObject)
    {
        UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\Diglett");
        // delete sym link
        IoDeleteSymbolicLink(&symLink);

        // delete device object
        IoDeleteDevice(DriverObject->DeviceObject);
        LogInfo("Diglett unloaded");
    }
#endif // LEGIT_DRIVER


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

//extern "C" void MainThread(PVOID StartContext)
//{
//    LogInfo("Main thread started\n");
//    auto increment = 0;
//    HANDLE ourThread = PsGetCurrentThreadId();
//    LogInfo("Our thread id:  %llu\n", (unsigned long long)ourThread);
//    auto cpuIndex = KeGetCurrentProcessorNumber();
//    LogInfo("Running on CPU: %lu", cpuIndex);
//    
//    PKTHREAD thisThread = (PKTHREAD)__readgsqword(0x188);
//
//    LogInfo("Hiding system thread:");
//    thisThread = reinterpret_cast<PKTHREAD>(KeGetCurrentThread());
//    LogInfo("\t\t\tKTHREAD->SystemThread = %lu", thisThread->SystemThread);
//    thisThread->SystemThread = 0;
//    LogInfo("\t\t\tKTHREAD->SystemThread = %lu", thisThread->SystemThread);
//
//    LogInfo("Spoofing thread entry point:");
//    _ETHREAD* myThread = reinterpret_cast<_ETHREAD*>(thisThread);
//    LogInfo("\t\t\t_ETHREAD->StartAddress = %p", myThread->StartAddress);
//    uintptr_t newWin32StartAddr = kernBase + 0x3000;
//    myThread->StartAddress = (PVOID)newWin32StartAddr;
//    LogInfo("\t\t\t_ETHREAD->StartAddress = %p", myThread->StartAddress);
//    LogInfo("\t\t\t_ETHREAD->Win32StartAddress = %p", myThread->Win32StartAddress);
//    myThread->Win32StartAddress = (PVOID)newWin32StartAddr;
//    LogInfo("\t\t\t_ETHREAD->Win32StartAddress = %p", myThread->Win32StartAddress);
//
//    while (runThread)
//    {
//        LARGE_INTEGER li;
//        li.QuadPart = -10000000;
//        KeDelayExecutionThread(KernelMode, FALSE, &li);
//    }
//    LogInfo("exiting thread\n");
//}

// Communication method via hook in legit driver control handler
//NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT tcpipDevObj, PIRP Irp)
//{
//    LogInfo("Hooked routine executed!\n");
//
//    // In the context of tcpip thread
//    auto stack = IoGetCurrentIrpStackLocation(Irp);
//    auto status = STATUS_SUCCESS;
//
//    switch (stack->Parameters.DeviceIoControl.IoControlCode)
//    {
//    case IOCTL_ECHO_REQUEST: {
//        LogInfo("IOCTL_ECHO_REQUEST received!!\n");
//        if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(ECHO_DATA))
//        {
//            status = STATUS_BUFFER_TOO_SMALL;
//            break;
//        }
//
//        auto data = (PECHO_DATA)stack->Parameters.DeviceIoControl.Type3InputBuffer;
//
//        if (data == nullptr)
//        {
//            status = STATUS_SUCCESS; // <- TEST
//            //status = STATUS_INVALID_PARAMETER;
//            break;
//        }
//
//        LogInfo("Echo request output: %s\n", data->strEcho);
//        Irp->IoStatus.Status = CUSTOM_STATUS;
//        Irp->IoStatus.Information = 0;
//        IoCompleteRequest(Irp, IO_NO_INCREMENT);
//        return CUSTOM_STATUS;
//    }
//    default:
//        LogInfo("Unrecognized IoControlCode, forwarding to original DeviceControl.\n");
//        return origDeviceControl(tcpipDevObj, Irp);
//    }
//
//    Irp->IoStatus.Status = status;
//    Irp->IoStatus.Information = 0;
//    IoCompleteRequest(Irp, IO_NO_INCREMENT);
//    return status;
//}

/// <summary>
/// Uses ZwQuerySysInfo to get legit module ranges
/// </summary>
/// <param name="ZwQuerySysInfo">pointer to ZwQuerySystemInformation</param>
/// <param name="outProcMods">pointer to struct with data out</param>
/// <returns>status</returns>
//NTSTATUS EnumKernelModuleInfo(_In_ ZwQuerySysInfoPtr ZwQuerySysInfo) {
//    ULONG size = NULL;
//    outProcMods = NULL;
//
//    // test our pointer
//    NTSTATUS status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, 0, 0, &size);
//    if (STATUS_INFO_LENGTH_MISMATCH == status) {
//        LogError("ZwQuerySystemInformation test successed, status: %08x", status);
//    }
//    else
//    {
//        LogError("Unexpected value from ZwQuerySystemInformation, status: %08x", status);
//        return status;
//    }
//
//    outProcMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, size);
//    if (!outProcMods) {
//        LogError("Insufficient memory in the free pool to satisfy the request");
//        return STATUS_UNSUCCESSFUL;
//    }
//
//    if (!NT_SUCCESS(status = ZwQuerySysInfo(SYSTEM_MODULE_INFORMATION, outProcMods, size, 0))) {
//        LogError("ZwQuerySystemInformation failed");
//        ExFreePool(outProcMods);
//        return status;
//    }
//
//    KdPrint(("Using ZwQuerySystemInformation with SYSTEM_MODULE_INFORMATION.  Modules->NumberOfModules = %lu\n", outProcMods->NumberOfModules));
//
//    for (ULONG i = 0; i < outProcMods->NumberOfModules; i++)
//    {
//        LogInfo("Module[%d].FullPathName: %s\n", (int)i, (char*)outProcMods->Modules[i].FullPathName);
//        LogInfo("Module[%d].ImageBase: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageBase);
//        LogInfo("Module[%d].MappedBase: %p\n", (int)i, (char*)outProcMods->Modules[i].MappedBase);
//        LogInfo("Module[%d].LoadCount: %p\n", (int)i, (char*)outProcMods->Modules[i].LoadCount);
//        LogInfo("Module[%d].ImageSize: %p\n", (int)i, (char*)outProcMods->Modules[i].ImageSize);
//    }
//
//    LogInfo("ZwQuerySystemInformation complete\n");
//    ExFreePool(outProcMods);
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