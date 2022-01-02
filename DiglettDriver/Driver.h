#pragma once
#include <ntifs.h>
#include <windef.h>
#include <ntstrsafe.h>
#include "PEHdr.h"

#define LEGIT_DRIVER
#define DEBUG

// @jk2
#ifdef DEBUG
#define Log(format, ...) DbgPrint("[DIGLETT] " format "\n", __VA_ARGS__)
#define LogInfo(format, ...) DbgPrint("[DIGLETT] [INFO] " format "\n", __VA_ARGS__)
#define LogError(format, ...) DbgPrint("[DIGLETT] [ERROR] " format "\n", __VA_ARGS__)

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

union _KWAIT_STATUS_REGISTER
{
    UCHAR Flags;                                                            //0x0
    UCHAR State : 3;                                                          //0x0
    UCHAR Affinity : 1;                                                       //0x0
    UCHAR Priority : 1;                                                       //0x0
    UCHAR Apc : 1;                                                            //0x0
    UCHAR UserApc : 1;                                                        //0x0
    UCHAR Alert : 1;                                                          //0x0
};

union _PS_CLIENT_SECURITY_CONTEXT
{
    ULONGLONG ImpersonationData;                                            //0x0
    VOID* ImpersonationToken;                                               //0x0
    ULONGLONG ImpersonationLevel : 2;                                         //0x0
    ULONGLONG EffectiveOnly : 1;                                              //0x0
};

struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

struct _PS_PROPERTY_SET
{
    struct _LIST_ENTRY ListHead;                                            //0x0
    ULONGLONG Lock;                                                         //0x10
};

struct _KTHREAD
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive : 1;                                        //0x74
            ULONG ReadyTransition : 1;                                        //0x74
            ULONG WaitNext : 1;                                               //0x74
            ULONG SystemAffinityActive : 1;                                   //0x74
            ULONG Alertable : 1;                                              //0x74
            ULONG UserStackWalkActive : 1;                                    //0x74
            ULONG ApcInterruptRequest : 1;                                    //0x74
            ULONG QuantumEndMigrate : 1;                                      //0x74
            ULONG UmsDirectedSwitchEnable : 1;                                //0x74
            ULONG TimerActive : 1;                                            //0x74
            ULONG SystemThread : 1;                                           //0x74
            ULONG ProcessDetachActive : 1;                                    //0x74
            ULONG CalloutActive : 1;                                          //0x74
            ULONG ScbReadyQueue : 1;                                          //0x74
            ULONG ApcQueueable : 1;                                           //0x74
            ULONG ReservedStackInUse : 1;                                     //0x74
            ULONG UmsPerformingSyscall : 1;                                   //0x74
            ULONG TimerSuspended : 1;                                         //0x74
            ULONG SuspendedWaitMode : 1;                                      //0x74
            ULONG SuspendSchedulerApcWait : 1;                                //0x74
            ULONG CetUserShadowStack : 1;                                     //0x74
            ULONG BypassProcessFreeze : 1;                                    //0x74
            ULONG Reserved : 10;                                              //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG ThreadFlagsSpare : 2;                                       //0x78
            ULONG AutoAlignment : 1;                                          //0x78
            ULONG DisableBoost : 1;                                           //0x78
            ULONG AlertedByThreadId : 1;                                      //0x78
            ULONG QuantumDonation : 1;                                        //0x78
            ULONG EnableStackSwap : 1;                                        //0x78
            ULONG GuiThread : 1;                                              //0x78
            ULONG DisableQuantum : 1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup : 1;                              //0x78
            ULONG DeferPreemption : 1;                                        //0x78
            ULONG QueueDeferPreemption : 1;                                   //0x78
            ULONG ForceDeferSchedule : 1;                                     //0x78
            ULONG SharedReadyQueueAffinity : 1;                               //0x78
            ULONG FreezeCount : 1;                                            //0x78
            ULONG TerminationApcRequest : 1;                                  //0x78
            ULONG AutoBoostEntriesExhausted : 1;                              //0x78
            ULONG KernelStackResident : 1;                                    //0x78
            ULONG TerminateRequestReason : 2;                                 //0x78
            ULONG ProcessStackCountDecremented : 1;                           //0x78
            ULONG RestrictedGuiThread : 1;                                    //0x78
            ULONG VpBackingThread : 1;                                        //0x78
            ULONG ThreadFlagsSpare2 : 1;                                      //0x78
            ULONG EtwStackTraceApcInserted : 8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy : 7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy : 1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode : 1;                                //0x7f
            UCHAR SpecCtrlSpare : 7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill[43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
        struct _LIST_ENTRY WaitListEntry;                                   //0xd8
        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
        struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4[20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5[68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6[116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7[164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8[40];                                       //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9[88];                                       //0x140
            struct _XSTATE_SAVE* XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10[136];                                     //0x140
            VOID* volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11[176];                                     //0x140
            struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
            struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
        };
    };
    union
    {
        volatile LONG ThreadFlags2;                                         //0x200
        struct
        {
            ULONG BamQosLevel : 8;                                            //0x200
            ULONG ThreadFlags2Reserved : 24;                                  //0x200
        };
    };
    ULONG Spare21;                                                          //0x204
    struct _LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber : 31;                                   //0x218
            ULONG SharedReadyQueue : 1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    union
    {
        struct _GROUP_AFFINITY UserAffinity;                                //0x228
        struct
        {
            UCHAR UserAffinityFill[10];                                     //0x228
            CHAR PreviousMode;                                              //0x232
            CHAR BasePriority;                                              //0x233
            union
            {
                CHAR PriorityDecrement;                                     //0x234
                struct
                {
                    UCHAR ForegroundBoost : 4;                                //0x234
                    UCHAR UnusualBoost : 4;                                   //0x234
                };
            };
            UCHAR Preempted;                                                //0x235
            UCHAR AdjustReason;                                             //0x236
            CHAR AdjustIncrement;                                           //0x237
        };
    };
    ULONGLONG AffinityVersion;                                              //0x238
    union
    {
        struct _GROUP_AFFINITY Affinity;                                    //0x240
        struct
        {
            UCHAR AffinityFill[10];                                         //0x240
            UCHAR ApcStateIndex;                                            //0x24a
            UCHAR WaitBlockCount;                                           //0x24b
            ULONG IdealProcessor;                                           //0x24c
        };
    };
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill[43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        struct _KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill0[1];                                     //0x288
            UCHAR ResourceIndex;                                            //0x289
        };
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3[64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4[72];                                    //0x288
            VOID* LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5[83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
    struct _LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    UCHAR AbAllocationRegionCount;                                          //0x31a
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    struct _KLOCK_ENTRY* LockEntries;                                       //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
    UCHAR PriorityFloorCounts[16];                                          //0x338
    UCHAR PriorityFloorCountsReserved[16];                                  //0x348
    ULONG PriorityFloorSummary;                                             //0x358
    volatile LONG AbCompletedIoBoostCount;                                  //0x35c
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
    volatile SHORT KeReferenceCount;                                        //0x364
    UCHAR AbOrphanedEntrySummary;                                           //0x366
    UCHAR AbOwnedEntryCount;                                                //0x367
    ULONG ForegroundLossTime;                                               //0x368
    union
    {
        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x370
        struct
        {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
            ULONGLONG InGlobalForegroundList;                               //0x378
        };
    };
    LONGLONG ReadOperationCount;                                            //0x380
    LONGLONG WriteOperationCount;                                           //0x388
    LONGLONG OtherOperationCount;                                           //0x390
    LONGLONG ReadTransferCount;                                             //0x398
    LONGLONG WriteTransferCount;                                            //0x3a0
    LONGLONG OtherTransferCount;                                            //0x3a8
    struct _KSCB* QueuedScb;                                                //0x3b0
    volatile ULONG ThreadTimerDelay;                                        //0x3b8
    union
    {
        volatile LONG ThreadFlags3;                                         //0x3bc
        struct
        {
            ULONG ThreadFlags3Reserved : 8;                                   //0x3bc
            ULONG PpmPolicy : 2;                                              //0x3bc
            ULONG ThreadFlags3Reserved2 : 22;                                 //0x3bc
        };
    };
    ULONGLONG TracingPrivate[1];                                            //0x3c0
    VOID* SchedulerAssist;                                                  //0x3c8
    VOID* volatile AbWaitObject;                                            //0x3d0
    ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
    ULONGLONG KernelWaitTime;                                               //0x3e0
    ULONGLONG UserWaitTime;                                                 //0x3e8
    union
    {
        struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
        struct
        {
            struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
            ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
        };
    };
    LONG SchedulerAssistPriorityFloor;                                      //0x400
    ULONG Spare28;                                                          //0x404
    ULONGLONG EndPadding[5];                                                //0x408
};

struct _ETHREAD
{
    struct _KTHREAD Tcb;                                                    //0x0
    union _LARGE_INTEGER CreateTime;                                        //0x430
    union
    {
        union _LARGE_INTEGER ExitTime;                                      //0x438
        struct _LIST_ENTRY KeyedWaitChain;                                  //0x438
    };
    union
    {
        struct _LIST_ENTRY PostBlockList;                                   //0x448
        struct
        {
            VOID* ForwardLinkShadow;                                        //0x448
            VOID* StartAddress;                                             //0x450
        };
    };
    union
    {
        struct _TERMINATION_PORT* TerminationPort;                          //0x458
        struct _ETHREAD* ReaperLink;                                        //0x458
        VOID* KeyedWaitValue;                                               //0x458
    };
    ULONGLONG ActiveTimerListLock;                                          //0x460
    struct _LIST_ENTRY ActiveTimerListHead;                                 //0x468
    struct _CLIENT_ID Cid;                                                  //0x478
    union
    {
        struct _KSEMAPHORE KeyedWaitSemaphore;                              //0x488
        struct _KSEMAPHORE AlpcWaitSemaphore;                               //0x488
    };
    union _PS_CLIENT_SECURITY_CONTEXT ClientSecurity;                       //0x4a8
    struct _LIST_ENTRY IrpList;                                             //0x4b0
    ULONGLONG TopLevelIrp;                                                  //0x4c0
    struct _DEVICE_OBJECT* DeviceToVerify;                                  //0x4c8
    VOID* Win32StartAddress;                                                //0x4d0
    VOID* ChargeOnlySession;                                                //0x4d8
    VOID* LegacyPowerObject;                                                //0x4e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x4e8
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x4f8
    struct _EX_PUSH_LOCK ThreadLock;                                        //0x500
    ULONG ReadClusterSize;                                                  //0x508
    volatile LONG MmLockOrdering;                                           //0x50c
    union
    {
        ULONG CrossThreadFlags;                                             //0x510
        struct
        {
            ULONG Terminated : 1;                                             //0x510
            ULONG ThreadInserted : 1;                                         //0x510
            ULONG HideFromDebugger : 1;                                       //0x510
            ULONG ActiveImpersonationInfo : 1;                                //0x510
            ULONG HardErrorsAreDisabled : 1;                                  //0x510
            ULONG BreakOnTermination : 1;                                     //0x510
            ULONG SkipCreationMsg : 1;                                        //0x510
            ULONG SkipTerminationMsg : 1;                                     //0x510
            ULONG CopyTokenOnOpen : 1;                                        //0x510
            ULONG ThreadIoPriority : 3;                                       //0x510
            ULONG ThreadPagePriority : 3;                                     //0x510
            ULONG RundownFail : 1;                                            //0x510
            ULONG UmsForceQueueTermination : 1;                               //0x510
            ULONG IndirectCpuSets : 1;                                        //0x510
            ULONG DisableDynamicCodeOptOut : 1;                               //0x510
            ULONG ExplicitCaseSensitivity : 1;                                //0x510
            ULONG PicoNotifyExit : 1;                                         //0x510
            ULONG DbgWerUserReportActive : 1;                                 //0x510
            ULONG ForcedSelfTrimActive : 1;                                   //0x510
            ULONG SamplingCoverage : 1;                                       //0x510
            ULONG ReservedCrossThreadFlags : 8;                               //0x510
        };
    };
    union
    {
        ULONG SameThreadPassiveFlags;                                       //0x514
        struct
        {
            ULONG ActiveExWorker : 1;                                         //0x514
            ULONG MemoryMaker : 1;                                            //0x514
            ULONG StoreLockThread : 2;                                        //0x514
            ULONG ClonedThread : 1;                                           //0x514
            ULONG KeyedEventInUse : 1;                                        //0x514
            ULONG SelfTerminate : 1;                                          //0x514
            ULONG RespectIoPriority : 1;                                      //0x514
            ULONG ActivePageLists : 1;                                        //0x514
            ULONG SecureContext : 1;                                          //0x514
            ULONG ZeroPageThread : 1;                                         //0x514
            ULONG WorkloadClass : 1;                                          //0x514
            ULONG ReservedSameThreadPassiveFlags : 20;                        //0x514
        };
    };
    union
    {
        ULONG SameThreadApcFlags;                                           //0x518
        struct
        {
            UCHAR OwnsProcessAddressSpaceExclusive : 1;                       //0x518
            UCHAR OwnsProcessAddressSpaceShared : 1;                          //0x518
            UCHAR HardFaultBehavior : 1;                                      //0x518
            volatile UCHAR StartAddressInvalid : 1;                           //0x518
            UCHAR EtwCalloutActive : 1;                                       //0x518
            UCHAR SuppressSymbolLoad : 1;                                     //0x518
            UCHAR Prefetching : 1;                                            //0x518
            UCHAR OwnsVadExclusive : 1;                                       //0x518
            UCHAR SystemPagePriorityActive : 1;                               //0x519
            UCHAR SystemPagePriority : 3;                                     //0x519
            UCHAR AllowUserWritesToExecutableMemory : 1;                      //0x519
            UCHAR AllowKernelWritesToExecutableMemory : 1;                    //0x519
            UCHAR OwnsVadShared : 1;                                          //0x519
        };
    };
    UCHAR CacheManagerActive;                                               //0x51c
    UCHAR DisablePageFaultClustering;                                       //0x51d
    UCHAR ActiveFaultCount;                                                 //0x51e
    UCHAR LockOrderState;                                                   //0x51f
    ULONG PerformanceCountLowReserved;                                      //0x520
    LONG PerformanceCountHighReserved;                                      //0x524
    ULONGLONG AlpcMessageId;                                                //0x528
    union
    {
        VOID* AlpcMessage;                                                  //0x530
        ULONG AlpcReceiveAttributeSet;                                      //0x530
    };
    struct _LIST_ENTRY AlpcWaitListEntry;                                   //0x538
    LONG ExitStatus;                                                        //0x548
    ULONG CacheManagerCount;                                                //0x54c
    ULONG IoBoostCount;                                                     //0x550
    ULONG IoQoSBoostCount;                                                  //0x554
    ULONG IoQoSThrottleCount;                                               //0x558
    ULONG KernelStackReference;                                             //0x55c
    struct _LIST_ENTRY BoostList;                                           //0x560
    struct _LIST_ENTRY DeboostList;                                         //0x570
    ULONGLONG BoostListLock;                                                //0x580
    ULONGLONG IrpListLock;                                                  //0x588
    VOID* ReservedForSynchTracking;                                         //0x590
    struct _SINGLE_LIST_ENTRY CmCallbackListHead;                           //0x598
    struct _GUID* ActivityId;                                               //0x5a0
    struct _SINGLE_LIST_ENTRY SeLearningModeListHead;                       //0x5a8
    VOID* VerifierContext;                                                  //0x5b0
    VOID* AdjustedClientToken;                                              //0x5b8
    VOID* WorkOnBehalfThread;                                               //0x5c0
    struct _PS_PROPERTY_SET PropertySet;                                    //0x5c8
    VOID* PicoContext;                                                      //0x5e0
    ULONGLONG UserFsBase;                                                   //0x5e8
    ULONGLONG UserGsBase;                                                   //0x5f0
    struct _THREAD_ENERGY_VALUES* EnergyValues;                             //0x5f8
    union
    {
        ULONGLONG SelectedCpuSets;                                          //0x600
        ULONGLONG* SelectedCpuSetsIndirect;                                 //0x600
    };
    struct _EJOB* Silo;                                                     //0x608
    struct _UNICODE_STRING* ThreadName;                                     //0x610
    struct _CONTEXT* SetContextState;                                       //0x618
    ULONG LastExpectedRunTime;                                              //0x620
    ULONG HeapData;                                                         //0x624
    struct _LIST_ENTRY OwnerEntryListHead;                                  //0x628
    ULONGLONG DisownedOwnerEntryListLock;                                   //0x638
    struct _LIST_ENTRY DisownedOwnerEntryListHead;                          //0x640
    //struct _KLOCK_ENTRY LockEntries[6];                                     //0x650
    VOID* CmDbgInfo;                                                        //0x890
};

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

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

	NTKERNELAPI NTSTATUS ObReferenceObjectByName(
		__in PUNICODE_STRING ObjectName,
		__in ULONG Attributes,
		__in_opt PACCESS_STATE AccessState,
		__in_opt ACCESS_MASK DesiredAccess,
		__in POBJECT_TYPE ObjectType,
		__in KPROCESSOR_MODE AccessMode,
		__inout_opt PVOID ParseContext,
		__out PVOID* Object
	);

	NTSTATUS NTAPI IoCreateDriver(
		_In_opt_ PUNICODE_STRING DriverName,
		_In_ PDRIVER_INITIALIZE InitializationFunction
	);

    NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(
            __in PEPROCESS Process
    );

	typedef void (*GenericFuncPtr)();
	typedef NTSTATUS(*ZwQuerySysInfoPtr)(ULONG, PVOID, ULONG, PULONG);
	typedef NTSTATUS(*DevCtrlPtr)(PDEVICE_OBJECT, PIRP Irp);

}

extern "C" __declspec(dllimport) POBJECT_TYPE * IoDriverObjectType;
//extern "C" NTSTATUS Hk_DeviceControl(PDEVICE_OBJECT, PIRP Irp);
//extern "C" void MainThread(PVOID StartContext);

//NTSTATUS EnumKernelModuleInfo(_In_ ZwQuerySysInfoPtr ZwQuerySysInfo);
PLOAD_IMAGE_NOTIFY_ROUTINE ImageNotifyRoutine(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcID, _In_ PIMAGE_INFO ImageInfo);
NTSTATUS DummyDrv_Init(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);
NTSTATUS SetHk_tcpip(_In_ BOOLEAN hook);
uintptr_t GetNtoskrnlBaseAddress();
#ifdef LEGIT_DRIVER
void Unload(_In_ PDRIVER_OBJECT DriverObject);
#endif