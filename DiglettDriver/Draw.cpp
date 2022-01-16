#pragma once
#include "Thread.h"
#include "Globals.h"
#include <ntifs.h>

void DrawMain(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);
    SpoofThread(DiglettDrv::gKernBase);
    LogInfo("DrawMain thread started");
    while (DiglettDrv::gRunThread)
    {
        LARGE_INTEGER li;
        li.QuadPart = -10000000;
        KeDelayExecutionThread(KernelMode, FALSE, &li);
    }
    LogInfo("DrawMain thread stopped");
}