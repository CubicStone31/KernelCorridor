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
}

