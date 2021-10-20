#pragma once

#include <ntifs.h>

extern "C"
{
    NTSTATUS ZwQuerySystemInformation(UINT64 SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    NTSTATUS NTAPI MmCopyVirtualMemory
    (
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );

    NTSTATUS NTAPI ZwProtectVirtualMemory
    (
        IN HANDLE ProcessHandle,
        IN OUT PVOID* BaseAddress,
        IN OUT SIZE_T* NumberOfBytesToProtect,
        IN ULONG NewAccessProtection,
        OUT PULONG OldAccessProtection
    );

    NTSTATUS NTAPI RtlCreateUserThread
    (
        IN HANDLE               ProcessHandle,
        IN PSECURITY_DESCRIPTOR SecurityDescriptor,
        IN BOOLEAN              CreateSuspended,
        IN ULONG                StackZeroBits,
        IN OUT PULONG           StackReserved,
        IN OUT PULONG           StackCommit,
        IN PVOID                StartAddress,
        IN PVOID                StartParameter,
        OUT PHANDLE             ThreadHandle,
        OUT PCLIENT_ID          ClientID
    );

    typedef BOOLEAN(*EX_ENUMERATE_HANDLE_ROUTINE)(
#if !defined(_WIN7_)
        IN PHANDLE_TABLE HandleTable,
#endif
        IN PHANDLE_TABLE_ENTRY HandleTableEntry,
        IN HANDLE Handle,
        IN PVOID EnumParameter
        );

    NTKERNELAPI
    BOOLEAN
    ExEnumHandleTable(
        IN PHANDLE_TABLE HandleTable,
        IN EX_ENUMERATE_HANDLE_ROUTINE EnumHandleProcedure,
        IN PVOID EnumParameter,
        OUT PHANDLE Handle
    );

    NTKERNELAPI
    VOID
    FASTCALL
    ExfUnblockPushLock(
        IN OUT PEX_PUSH_LOCK PushLock,
        IN OUT PVOID WaitBlock
    );

    typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
        PVOID NormalContext,
        PVOID SystemArgument1,
        PVOID SystemArgument2
        );

    typedef enum _KAPC_ENVIRONMENT
    {
        OriginalApcEnvironment,
        AttachedApcEnvironment,
        CurrentApcEnvironment,
        InsertApcEnvironment
    } KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

    typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
        PRKAPC Apc,
        PKNORMAL_ROUTINE* NormalRoutine,
        PVOID* NormalContext,
        PVOID* SystemArgument1,
        PVOID* SystemArgument2
        );

    typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

    NTKERNELAPI
        VOID
        NTAPI
        KeInitializeApc(
            IN PKAPC Apc,
            IN PKTHREAD Thread,
            IN KAPC_ENVIRONMENT ApcStateIndex,
            IN PKKERNEL_ROUTINE KernelRoutine,
            IN PKRUNDOWN_ROUTINE RundownRoutine,
            IN PKNORMAL_ROUTINE NormalRoutine,
            IN KPROCESSOR_MODE ApcMode,
            IN PVOID NormalContext
        );

    NTKERNELAPI
        PVOID
        NTAPI
        PsGetCurrentProcessWow64Process();

    NTKERNELAPI
        BOOLEAN
        NTAPI
        KeTestAlertThread(IN KPROCESSOR_MODE AlertMode);

    NTKERNELAPI
        BOOLEAN
        NTAPI
        KeInsertQueueApc(
            PKAPC Apc,
            PVOID SystemArgument1,
            PVOID SystemArgument2,
            KPRIORITY Increment
        );
}

