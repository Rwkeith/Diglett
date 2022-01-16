#include "Thread.h"

void SpoofThread(PVOID newThreadEntry)
{
    LogInfo("Main thread started\n");
    auto increment = 0;
    HANDLE ourThread = PsGetCurrentThreadId();
    LogInfo("Our thread id:  %llu\n", (unsigned long long)ourThread);
    auto cpuIndex = KeGetCurrentProcessorNumber();
    LogInfo("Running on CPU: %lu", cpuIndex);

    PKTHREAD thisThread = (PKTHREAD)__readgsqword(0x188);

    LogInfo("Hiding system thread.");
    thisThread = reinterpret_cast<PKTHREAD>(KeGetCurrentThread());
    LogInfo("\t\t\tKTHREAD->SystemThread = %lu", thisThread->SystemThread);
    thisThread->SystemThread = 0;
    LogInfo("\t\t\tKTHREAD->SystemThread = %lu", thisThread->SystemThread);

    LogInfo("Spoofing thread entry point.");
    _ETHREAD* myThread = reinterpret_cast<_ETHREAD*>(thisThread);
    
    LogInfo("\t\t\tOld: _ETHREAD->StartAddress = %p", myThread->StartAddress);
    // kernBase + 0x3000;
    myThread->StartAddress = newThreadEntry;
    LogInfo("\t\t\tNew: _ETHREAD->StartAddress = %p", myThread->StartAddress);
    
    LogInfo("\t\t\tOld:  _ETHREAD->Win32StartAddress = %p", myThread->Win32StartAddress);
    myThread->Win32StartAddress = newThreadEntry;
    LogInfo("\t\t\tNew:  _ETHREAD->Win32StartAddress = %p", myThread->Win32StartAddress);
}