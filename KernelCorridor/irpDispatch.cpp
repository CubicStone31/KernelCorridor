#include <ntifs.h>
#include "khelper/khelper.h"
#include "interface.h"

void Handler_ReadProcessMemory(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = inputBuffer;
    ULONG outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_READ_PROCESS_MEM))
    {
        return;
    }

    KCProtocols::REQUEST_READ_PROCESS_MEM* request = (KCProtocols::REQUEST_READ_PROCESS_MEM*)inputBuffer;
    if (outputSize < request->size + sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM))
    {
        return;
    }

    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)request->pid, &process)))
    {
        return;
    }

    KCProtocols::RESPONSE_READ_PROCESS_MEM* response = (KCProtocols::RESPONSE_READ_PROCESS_MEM*)outputBuffer;
    if (request->method == KCProtocols::MEM_ACCESS_METHOD::MmCopyVirtualMemory)
    {
        if (KHelper::Common::ReadProcessMemory(process, (PVOID)request->addr, response->data, request->size, &response->size))
        {
            ObDereferenceObject(process);
            return;
        }
    }
    else if (request->method == KCProtocols::MEM_ACCESS_METHOD::MapToKernelByMdl)
    {
        if (KHelper::Common::ReadProcessMemoryByMdl(process, (PVOID)request->addr, response->data, request->size, &response->size))
        {
            ObDereferenceObject(process);
            return;
        }
    }
    else
    {
        ObDereferenceObject(process);
        return;
    }

    ObDereferenceObject(process);
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputSize;
    return;
}

void Handler_WriteProcessMemory(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = inputBuffer;
    ULONG outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) || outputSize < sizeof(KCProtocols::RESPONSE_WRITE_PROCESS_MEM))
    {
        return;
    }

    KCProtocols::REQUEST_WRITE_PROCESS_MEM* request = (KCProtocols::REQUEST_WRITE_PROCESS_MEM*)inputBuffer;
    if (inputSize < sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + request->size)
    {
        return;
    }

    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)request->pid, &process)))
    {
        return;
    }

    SIZE_T bytesWritten = 0;
    if (request->method == KCProtocols::MEM_ACCESS_METHOD::MmCopyVirtualMemory)
    {
        if (KHelper::Common::WriteProcessMemory(process, (PVOID)request->addr, request->data, request->size, &bytesWritten))
        {
            ObDereferenceObject(process);
            return;
        }
    }
    else if (request->method == KCProtocols::MEM_ACCESS_METHOD::MapToKernelByMdl)
    {
        if (KHelper::Common::WriteProcessMemoryByMdl(process, (PVOID)request->addr, request->data, request->size, &bytesWritten))
        {
            ObDereferenceObject(process);
            return;
        }
    }

    ObDereferenceObject(process);
    KCProtocols::RESPONSE_WRITE_PROCESS_MEM* response = (KCProtocols::RESPONSE_WRITE_PROCESS_MEM*)outputBuffer;
    response->bytesWritten = (decltype(response->bytesWritten))bytesWritten;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputSize;
    return;
}

void Handler_CreateUserThread(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = inputBuffer;
    ULONG outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_CREATE_USER_THREAD) || outputSize < sizeof(KCProtocols::RESPONSE_CREATE_USER_THREAD))
    {
        return;
    }

    KCProtocols::REQUEST_CREATE_USER_THREAD* request = (KCProtocols::REQUEST_CREATE_USER_THREAD*)inputBuffer;
    KCProtocols::RESPONSE_CREATE_USER_THREAD* response = (KCProtocols::RESPONSE_CREATE_USER_THREAD*)outputBuffer;

    CLIENT_ID clientId = {};
    clientId.UniqueProcess = (HANDLE)request->pid;
    clientId.UniqueThread = 0;
    OBJECT_ATTRIBUTES objectAttributes = {};
    InitializeObjectAttributes(&objectAttributes, NULL, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    ACCESS_MASK desiredAccess = PROCESS_ALL_ACCESS;
    HANDLE processHandle = 0;
    if (!NT_SUCCESS(ZwOpenProcess(&processHandle, desiredAccess, &objectAttributes, &clientId)))
    {
        return;
    }

    HANDLE thread;
    clientId = {};
    if (!NT_SUCCESS(KHelper::Common::CreateUserModeThread(processHandle, (PVOID)request->startAddr, (PVOID)request->parameter, request->createSuspended, &thread, &clientId)))
    {
        ZwClose(processHandle);
        return;
    }

    ZwClose(processHandle);
    ZwClose(thread);
    response->processID = (UINT32)clientId.UniqueProcess;
    response->threadID = (UINT32)clientId.UniqueThread;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputSize;
    return;
}

void Handler_InitUndocumentedData(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_INIT_UNDOCUMENTED_DATA))
    {
        return;
    }

    KCProtocols::REQUEST_INIT_UNDOCUMENTED_DATA* request = (KCProtocols::REQUEST_INIT_UNDOCUMENTED_DATA*)inputBuffer;
    switch (request->type)
    {
    case KCProtocols::UNDOCUMENTED_DATA_TYPE::EPROCESS_ImageFileName_Offset:
    {
        KHelper::UnDocumentedData::EPROCESS_ImageFileName_Offset = (UINT32)request->data;
        break;
    }
    case KCProtocols::UNDOCUMENTED_DATA_TYPE::EPROCESS_Protection_Offset:
    {
        KHelper::UnDocumentedData::EPROCESS_Protection_Offset = (UINT32)request->data;
        break;
    }
    case KCProtocols::UNDOCUMENTED_DATA_TYPE::EPROCESS_ObjectTable_Offset:
    {
        KHelper::UnDocumentedData::EPROCESS_ObjectTable_Offset = (UINT32)request->data;
        break;
    }
    case KCProtocols::UNDOCUMENTED_DATA_TYPE::DriverSignatureEnforcement_Offset:
    {
        KHelper::UnDocumentedData::DriverSignatureEnforcement_Offset = (UINT32)request->data;
        break;
    }
    }
    
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;
    return;
}

void Handler_SetProcessProtectionField(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = inputBuffer;
    ULONG outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_SET_PROCESS_PROTECTION_FIELD) || outputSize < sizeof(KCProtocols::RESPONSE_SET_PROCESS_PROTECTION_FIELD))
    {
        return;
    }

    auto request = (KCProtocols::REQUEST_SET_PROCESS_PROTECTION_FIELD*)inputBuffer;
    auto response = (KCProtocols::RESPONSE_SET_PROCESS_PROTECTION_FIELD*)outputBuffer;
    
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)request->pid, &process)))
    {
        return;
    }
    
    UINT8 protect = request->newProtect;
    if (!NT_SUCCESS(KHelper::Common::SetProcessProtectionField(process, &protect, request->queryOnly)))
    {
        ObDereferenceObject(process);
        return;
    }
    ObDereferenceObject(process);

    response->oldProtect = protect;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputSize;
    return;
}

void Handler_ChangeHandleAccess(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = inputBuffer;
    ULONG outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_SET_HANDLE_ACCESS) || outputSize < sizeof(KCProtocols::RESPONSE_SET_HANDLE_ACCESS))
    {
        return;
    }
    KCProtocols::REQUEST_SET_HANDLE_ACCESS* request = (KCProtocols::REQUEST_SET_HANDLE_ACCESS*)inputBuffer;
    KCProtocols::RESPONSE_SET_HANDLE_ACCESS* response = (KCProtocols::RESPONSE_SET_HANDLE_ACCESS*)outputBuffer;

    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)request->pid, &process)))
    {
        return;
    }

    UINT32 access = request->newAccess;
    if (!NT_SUCCESS(KHelper::Common::SetUserHandleAccess(process, (PVOID)request->handle, &access, request->queryOnly)))
    {
        ObDereferenceObject(process);
        return;
    }

    ObDereferenceObject(process);
    response->oldAccess = access;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputSize;
    return;
}

void Handler_DeleteFile(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_DELETE_FILE))
    {
        return;
    }
    auto request = (KCProtocols::REQUEST_DELETE_FILE*)inputBuffer;

    UNICODE_STRING str = {};
    RtlInitUnicodeString(&str, request->path);
    if (!NT_SUCCESS(KHelper::Common::DeleteFile1(&str)))
    {
        return;
    }
  
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    return;
}

void Handler_BSOD(PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pIrp);
    KHelper::Common::BSOD();
}

void Handler_SetDSE(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = inputBuffer;
    ULONG outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;

    if (inputSize < sizeof(KCProtocols::REQUEST_SET_DSE) || outputSize < sizeof(KCProtocols::RESPONSE_SET_DSE))
    {
        return;
    }
    KCProtocols::REQUEST_SET_DSE* request = (KCProtocols::REQUEST_SET_DSE*)inputBuffer;
    KCProtocols::RESPONSE_SET_DSE* response = (KCProtocols::RESPONSE_SET_DSE*)outputBuffer;

    DWORD dseValue = request->value;
    if (!NT_SUCCESS(KHelper::Common::SetDSE(&dseValue, request->queryOnly)))
    {
        return;
    }

    response->oldValue = dseValue;
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputSize;
    return;
}

void Handler_AllocateMemory(PIRP pIrp)
{
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    PVOID inputBuffer = pIrp->AssociatedIrp.SystemBuffer;
    ULONG inputSize = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID outputBuffer = inputBuffer;
    ULONG outputSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
    pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
    pIrp->IoStatus.Information = 0;
    if (inputSize < sizeof(KCProtocols::REQUEST_ALLOC_PROCESS_MEM) || outputSize < sizeof(KCProtocols::RESPONSE_ALLOC_PROCESS_MEM))
    {
        return;
    }
    auto request = (KCProtocols::REQUEST_ALLOC_PROCESS_MEM*)inputBuffer;
    auto response = (KCProtocols::RESPONSE_ALLOC_PROCESS_MEM*)outputBuffer;

    PEPROCESS process = NULL;
    auto status = PsLookupProcessByProcessId((HANDLE)request->pid, &process);
    if (!NT_SUCCESS(status))
    {
        return;
    }
    KAPC_STATE apc;
    KeStackAttachProcess(process, &apc);
    if (!request->isFree)
    {
        SIZE_T size = request->length;
        PVOID base = (PVOID)request->addr;
        status = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0, &size, MEM_COMMIT, request->protect);
        if (!NT_SUCCESS(status))
        {
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(process);
            return;
        }
        response->base = (UINT64)base;
    }
    else
    {
        // free the memory
        SIZE_T size = 0;
        if (!NT_SUCCESS(ZwFreeVirtualMemory(ZwCurrentProcess(), (PVOID*)&request->addr, &size, MEM_RELEASE)))
        {
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(process);
            return;
        }
    }
    
    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(process);
    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = outputSize;
    return;
}

NTSTATUS IRPDispatch(PDRIVER_OBJECT device, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(device);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(pIrp);
    ULONG cc = stack->Parameters.DeviceIoControl.IoControlCode;

    switch (cc)
    {
    case CC_READ_PROCESS_MEM:
    {
        Handler_ReadProcessMemory(pIrp);
        break;
    }
    case CC_WRITE_PROCESS_MEM:
    {
        Handler_WriteProcessMemory(pIrp);
        break;
    }
    case CC_CREATE_USER_THREAD:
    {
        Handler_CreateUserThread(pIrp);
        break;
    }
    case CC_SET_PROCESS_PROTECTION_FIELD:
    {
        Handler_SetProcessProtectionField(pIrp);
        break;
    }
    case CC_INIT_UNDOCUMENTED_DATA:
    {
        Handler_InitUndocumentedData(pIrp);
        break;
    }
    case CC_SET_HADNLE_ACCESS:
    {
        Handler_ChangeHandleAccess(pIrp);
        break;
    }
    case CC_DELETE_FILE:
    {
        Handler_DeleteFile(pIrp);
        break;
    }
    case CC_BSOD:
    {
        Handler_BSOD(pIrp);
        break;
    }
    case CC_SET_DSE:
    {
        Handler_SetDSE(pIrp);
        break;
    }
    case CC_ALLOC_PROCESS_MEM:
    {
        Handler_AllocateMemory(pIrp);
        break;
    }
    default:
    {
        pIrp->IoStatus.Information = 0;
        pIrp->IoStatus.Status = STATUS_SUCCESS;
    }
    }

    NTSTATUS ioStatus = pIrp->IoStatus.Status;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return ioStatus;
}