#pragma once
#include "Utility.h"
#include "Driver.h"
#include "Common.h"
#include "Draw.h"

void* gOriginalDispatchFunctionArray[IRP_MJ_MAXIMUM_FUNCTION];
PFAST_IO_DEVICE_CONTROL gOriginalFastIoControl = NULL;

namespace DiglettDrv
{
    void* gKernBase;
    bool gRunThread;
}


#ifdef LEGIT_DRIVER
    NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
#else
    extern "C" NTSTATUS DriverEntry()
#endif // LEGIT_DRIVER
{
        DiglettDrv::gKernBase = (void*)GetNtoskrnlBaseAddress();
#ifdef LEGIT_DRIVER
        UNREFERENCED_PARAMETER(RegistryPath);
        Log("DriverEntry() Starting Diglett as legit driver!");
        Log("Current IRQL: %d", (int)KeGetCurrentIrql());
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
            LogError("Failed to create symbolic link (0x%08X)", status);
            IoDeleteDevice(DeviceObject);
            return status;
        }

        LogInfo("Driver initialized successfully");
#else
        Log("DriverEntry() Starting Diglett as manually mapped driver!\n");
#endif // LEGIT_DRIVER
    
    UINT64 outBase = 0;
    UINT64 outSize = 0;
    Utility::GetUserModBase("unused.dll", 6088, &outBase, &outSize);

#ifdef USERLAND_COMMUNICATE
    SetHook(true);
#endif // USERLAND_COMMUNICATE

#ifdef USE_SYSTEM_THREAD
    HANDLE threadHandle;
    PsCreateSystemThread(&threadHandle, GENERIC_ALL, 0, 0, 0, DrawThread, 0);
    ZwClose(threadHandle);
#endif // USE_SYSTEM_THREAD

    LogInfo("~DriverEntry()");
    return STATUS_SUCCESS;
}

#ifdef LEGIT_DRIVER
    void Unload(_In_ PDRIVER_OBJECT DriverObject)
    {
#ifdef USERLAND_COMMUNICATE
        SetHook(false);
#endif // USERLAND_COMMUNICATE

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

/* hook/unhook driver */
NTSTATUS SetHook(BOOL setHook)
{
    UNICODE_STRING driverName;
    UNICODE_STRING newDrvName;
    //PDRIVER_OBJECT tcpipDrvObj;
    DRIVER_OBJECT myDummyDriver;
    PDEVICE_OBJECT tcpipDevice;
    PDRIVER_OBJECT DriverObject = NULL;
    NTSTATUS status;
    PDRIVER_OBJECT dummyDriver;
    //HANDLE fileHandle;
    //UNICODE_STRING fileName = RTL_CONSTANT_STRING(L"\\DosDevices\\C:\\\\Windows\\System32\\drivers\\tcpip.sys");
    //OBJECT_ATTRIBUTES objAttr;
    //IO_STATUS_BLOCK ioStatusBlock;

    // Psched works well!
    //RtlInitUnicodeString(&driverName, L"\\Driver\\Psched");
    RtlInitUnicodeString(&driverName, L"\\Driver\\Null");

    status = ObReferenceObjectByName(&driverName, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject);

    if (!NT_SUCCESS(status)) {
        LogError("Failed to obtain DriverObject (0x%08X)", status);
        return status;
    }

    if (setHook)
    {
        LogInfo("Hooking Null driver major funcs...");
        for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
            //save the original pointer in case we need to restore it later
            gOriginalDispatchFunctionArray[i] = DriverObject->MajorFunction[i];
            //replace the pointer with our own pointer
            if (i == IRP_MJ_CREATE)
            {
                DriverObject->MajorFunction[i] = Hk_Create;
                LogInfo("\tHooked IRP_MJ_CREATE");
                LogInfo("\t\tOld: %p", gOriginalDispatchFunctionArray[i]);
                LogInfo("\t\tNew: %p", DriverObject->MajorFunction[i]);
            }
            if (i == IRP_MJ_DEVICE_CONTROL)
            {
                DriverObject->MajorFunction[i] = Hk_DeviceControl;
                LogInfo("\tHooked IRP_MJ_DEVICE_CONTROL");
                LogInfo("\t\tOld: %p", gOriginalDispatchFunctionArray[i]);
                LogInfo("\t\tNew: %p", DriverObject->MajorFunction[i]);
            }
        }
        
        LogInfo("Hooking Null driver object FastIoDispatch->FastIoDeviceControl...");
        gOriginalFastIoControl = DriverObject->FastIoDispatch->FastIoDeviceControl;
        DriverObject->FastIoDispatch->FastIoDeviceControl = (PFAST_IO_DEVICE_CONTROL)Hk_FastIoDispatch;
        LogInfo("\t\tOld: %p", gOriginalFastIoControl);
        LogInfo("\t\tNew: %p", DriverObject->FastIoDispatch->FastIoDeviceControl);
    }
    else
    {
        for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
            DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)gOriginalDispatchFunctionArray[i];
        }
        LogInfo("Unhooked Null driver major functions...");

        DriverObject->FastIoDispatch->FastIoDeviceControl = gOriginalFastIoControl;
        LogInfo("\tUnhooked ->FastIoDispatch->FastIoDeviceControl");
    }

    //cleanup
    ObDereferenceObject(DriverObject);

    return STATUS_SUCCESS;
}

BOOLEAN Hk_FastIoDispatch(
    _In_ _FILE_OBJECT* FileObject,
    _In_ BOOLEAN Wait,
    _In_opt_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_opt_ PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _In_ ULONG IoControlCode,
    _Out_ PIO_STATUS_BLOCK IoStatus,
    _In_ _DEVICE_OBJECT* DeviceObject)
{
    LogInfo("Hk_FastIoDispatch executed in Diglett!");

    switch (IoControlCode)
    {
    case IOCTL_DRAW_START: {
        DiglettDrv::gRunThread = true;
        LogInfo("Starting Draw Thread.");
        HANDLE threadHandle;
        PsCreateSystemThread(&threadHandle, GENERIC_ALL, 0, 0, 0, DrawMain, 0);
        ZwClose(threadHandle);
        break;
    }
    case IOCTL_DRAW_STOP: {
        LogInfo("Stopping Draw Thread.");
        DiglettDrv::gRunThread = false;
        break;
    }
    default:
        break;
    }

    if (!gOriginalFastIoControl)
    {
        return 0;
    }
    
    return gOriginalFastIoControl(
        FileObject,
        Wait,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength,
        IoControlCode,
        IoStatus,
        DeviceObject);
}

NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    LogInfo("IRP_MJ_DEVICE_CONTROL hook executed in Diglett!");
    return ((DevCtrlPtr)(gOriginalDispatchFunctionArray[IRP_MJ_DEVICE_CONTROL]))(DeviceObject, Irp);
}

NTSTATUS Hk_Create(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    LogInfo("IRP_MJ_CREATE hook executed in Diglett!");
    return ((DevCtrlPtr)(gOriginalDispatchFunctionArray[IRP_MJ_CREATE]))(DeviceObject, Irp);
}

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