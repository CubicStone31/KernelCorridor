#include "khelper.h"
#include "kdefs.h"
#include "undocumentedAPIs.h"

#define EX_ADDITIONAL_INFO_SIGNATURE (ULONG_PTR)(-2)
#define ExpIsValidObjectEntry(Entry) \
    ( (Entry != NULL) && (Entry->LowValue != 0) && (Entry->HighValue != EX_ADDITIONAL_INFO_SIGNATURE) )

UINT32 KHelper::UnDocumentedData::EPROCESS_ImageFileName_Offset = KHelper::UnDocumentedData::INVALID_DATA_VALUE;
UINT32 KHelper::UnDocumentedData::EPROCESS_Protection_Offset = KHelper::UnDocumentedData::INVALID_DATA_VALUE;
UINT32 KHelper::UnDocumentedData::EPROCESS_ObjectTable_Offset = KHelper::UnDocumentedData::INVALID_DATA_VALUE;
UINT32 KHelper::UnDocumentedData::DriverSignatureEnforcement_Offset = KHelper::UnDocumentedData::INVALID_DATA_VALUE;
bool KHelper::Common::VirtualDeviceCreated = false;
PDEVICE_OBJECT KHelper::Common::Device = NULL;
UNICODE_STRING KHelper::Common::DeviceName = {};
UNICODE_STRING KHelper::Common::SymLinkName = {};

bool GeneralUserModeMemoryCheck(PEPROCESS process, PVOID addr, SIZE_T size)
{
    UNREFERENCED_PARAMETER(process);

    if (size >= 0xffffffff || size == 0)
    {
        return false;
    }

    if (!KHelper::Common::IsUserModeAddress(addr))
    {
        return false;
    }

    if (!KHelper::Common::IsUserModeAddress((char*)addr + size))
    {
        return false;
    }

    return true;
}

PVOID KHelper::Common::GetModuleBaseAddress64A(char* module_name)
{
    ULONG needlen = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &needlen);
    PVOID buffer = ExAllocatePool(NonPagedPool, needlen);
    ZwQuerySystemInformation(11, buffer, needlen, &needlen);

    PRTL_PROCESS_MODULE_INFORMATION pSysModuleInfo;
    UINT32 Modcnt = 0;
    Modcnt = *(UINT32*)buffer;
    pSysModuleInfo = (PRTL_PROCESS_MODULE_INFORMATION)((char*)buffer + sizeof(PVOID));
    for (UINT32 i = 0; i < Modcnt; i++)
    {
        if (String::FindSubStringCaseInsensitiveA((char*)pSysModuleInfo->FullPathName, module_name))
        {
            PVOID ret = pSysModuleInfo->ImageBase;
            ExFreePool(buffer);
            return ret;
        }
        pSysModuleInfo++;
    }
    ExFreePool(buffer);
    return 0;
}

PVOID KHelper::Common::KernelGetProcAddress(PVOID ModuleBase, PCHAR pFunctionName)
{
    if (!ModuleBase || !pFunctionName)
    {
        return 0;
    }

    PVOID pFunctionAddress = NULL;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ModuleBase;
        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((UINT64)ModuleBase + dos->e_lfanew);

        PIMAGE_DATA_DIRECTORY expdir = (PIMAGE_DATA_DIRECTORY)(nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
        ULONG  addr = expdir->VirtualAddress;
        PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((UINT64)ModuleBase + addr);

        PULONG functions = (PULONG)((UINT64)ModuleBase + exports->AddressOfFunctions);
        PSHORT ordinals = (PSHORT)((UINT64)ModuleBase + exports->AddressOfNameOrdinals);
        PULONG names = (PULONG)((UINT64)ModuleBase + exports->AddressOfNames);
        ULONG  max_name = exports->NumberOfNames;
        ULONG  max_func = exports->NumberOfFunctions;

        ULONG i;

        for (i = 0; i < max_name; i++)
        {
            ULONG ord = ordinals[i];
            if (i >= max_name || ord >= max_func) {
                return NULL;
            }
            if (functions[ord] < addr || functions[ord] >= addr) // SIZE?
            {
                if (strcmp((PCHAR)ModuleBase + names[i], pFunctionName) == 0)
                {
                    pFunctionAddress = (PVOID)((PCHAR)ModuleBase + functions[ord]);
                    break;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        pFunctionAddress = NULL;
    }
    return pFunctionAddress;
}

NTSTATUS KHelper::Common::ReadProcessMemory(PEPROCESS process, PVOID sourceAddr, PVOID targetAddr, SIZE_T size, SIZE_T* returnedSize)
{
    if (!GeneralUserModeMemoryCheck(process, sourceAddr, size))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return MmCopyVirtualMemory(process, sourceAddr, PsGetCurrentProcess(), targetAddr, size, KernelMode, returnedSize);
}

NTSTATUS KHelper::Common::WriteProcessMemory(PEPROCESS process, PVOID targetAddr, PVOID sourceAddr, SIZE_T size, SIZE_T* sizeWritten)
{
    if (!GeneralUserModeMemoryCheck(process, targetAddr, size))
    {
        return STATUS_UNSUCCESSFUL;
    }

    return MmCopyVirtualMemory(PsGetCurrentProcess(), sourceAddr, process, targetAddr, size, KernelMode, sizeWritten);
}

NTSTATUS KHelper::Common::ReadProcessMemoryByMdl(PEPROCESS process, PVOID sourceAddr, PVOID targetAddr, SIZE_T size, SIZE_T* returnedSize)
{
    if (!GeneralUserModeMemoryCheck(process, sourceAddr, size))
    {
        return STATUS_UNSUCCESSFUL;
    }

    bool processAttached = false;
    bool mdlAllocated = false;
    bool protectionChanged = false;
    bool memoryLocked = false;
    bool systemAddrMapped = false;
    KAPC_STATE apc = {};
    PMDL mdl = 0;
    PVOID baseAddr = 0;
    SIZE_T bytesToProtect = 0;
    ULONG oldProtect = 0;
    PVOID data = 0;
    NTSTATUS ret = STATUS_SUCCESS;

    do
    {
        KeStackAttachProcess(process, &apc);
        processAttached = true;

        mdl = IoAllocateMdl(sourceAddr, (ULONG)size, false, false, 0);
        if (mdl == NULL)
        {
            kprintf("IoAllocateMdl failed.\n");
            ret = STATUS_UNSUCCESSFUL;
            break;
        }
        mdlAllocated = true;

        baseAddr = sourceAddr;
        bytesToProtect = size;
        oldProtect = 0;
        if (auto status = ZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &bytesToProtect, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            kprintf("ZwProtectVirtualMemory failed.\n");
            ret = status;
            break;
        }
        protectionChanged = true;

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
            memoryLocked = true;

            data = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
            if (data == NULL)
            {
                kprintf("MmGetSystemAddressForMdlSafe failed.\n");
                ret = STATUS_UNSUCCESSFUL;
                break;
            }
            systemAddrMapped = true;

            RtlCopyMemory(targetAddr, data, size);
            *returnedSize = size;
            ret = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            kprintf("MmProbeAndLockPages failed.\n");
            ret = STATUS_UNSUCCESSFUL;
            break;
        }

    } while (0);

    if (systemAddrMapped)
    {
        MmUnmapLockedPages(data, mdl);
    }
    if (memoryLocked)
    {
        MmUnlockPages(mdl);
    }
    if (protectionChanged)
    {
        ZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &bytesToProtect, oldProtect, &oldProtect);
    }
    if (mdlAllocated)
    {
        IoFreeMdl(mdl);
    }
    if (processAttached)
    {
        KeUnstackDetachProcess(&apc);
    }
    return ret;
}

NTSTATUS KHelper::Common::WriteProcessMemoryByMdl(PEPROCESS process, PVOID targetAddr, PVOID sourceAddr, SIZE_T size, SIZE_T* sizeWritten)
{
    if (!GeneralUserModeMemoryCheck(process, targetAddr, size))
    {
        kprintf("%s: GeneralUserModeMemoryCheck failed.\n", __FUNCTION__);
        return STATUS_UNSUCCESSFUL;
    }

    bool processAttached = false;
    bool mdlAllocated = false;
    bool protectionChanged = false;
    bool memoryLocked = false;
    bool systemAddrMapped = false;
    KAPC_STATE apc = {};
    PMDL mdl = 0;
    PVOID baseAddr = 0;
    SIZE_T bytesToProtect = 0;
    ULONG oldProtect = 0;
    PVOID data = 0;
    NTSTATUS ret = STATUS_SUCCESS;

    do
    {
        KeStackAttachProcess(process, &apc);
        processAttached = true;

        mdl = IoAllocateMdl(targetAddr, (ULONG)size, false, false, 0);
        if (mdl == NULL)
        {
            kprintf("%s: IoAllocateMdl failed.\n", __FUNCTION__);
            ret = STATUS_UNSUCCESSFUL;
            break;
        }
        mdlAllocated = true;

        baseAddr = targetAddr;
        bytesToProtect = size;
        oldProtect = 0;
        if (auto status = ZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &bytesToProtect, PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            kprintf("%s: ZwProtectVirtualMemory failed with %u.\n", __FUNCTION__, status);
            ret = status;
            break;
        }
        protectionChanged = true;

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
            memoryLocked = true;

            data = MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);
            if (data == NULL)
            {
                kprintf("%s: MmGetSystemAddressForMdlSafe failed.\n", __FUNCTION__);
                ret = STATUS_UNSUCCESSFUL;
                break;
            }
            systemAddrMapped = true;

            RtlCopyMemory(data, sourceAddr, size);
            *sizeWritten = size;
            ret = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            kprintf("%s: MmProbeAndLockPages failed.\n", __FUNCTION__);
            ret = STATUS_UNSUCCESSFUL;
            break;
        }

    } while (0);

    if (systemAddrMapped)
    {
        MmUnmapLockedPages(data, mdl);
    }
    if (memoryLocked)
    {
        MmUnlockPages(mdl);
    }
    if (protectionChanged)
    {
        ZwProtectVirtualMemory(ZwCurrentProcess(), &baseAddr, &bytesToProtect, oldProtect, &oldProtect);
    }
    if (mdlAllocated)
    {
        IoFreeMdl(mdl);
    }
    if (processAttached)
    {
        KeUnstackDetachProcess(&apc);
    }
    return ret;
}

NTSTATUS KHelper::Common::SetProcessProtectionField(PEPROCESS process, UINT8* protect, bool queryOnly)
{
    if (UnDocumentedData::EPROCESS_Protection_Offset == UnDocumentedData::INVALID_DATA_VALUE)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    UINT8 oldProtect = *((UINT8*)process + UnDocumentedData::EPROCESS_Protection_Offset);
    if (!queryOnly)
    {
        *((UINT8*)process + UnDocumentedData::EPROCESS_Protection_Offset) = *protect;
    }
    *protect = oldProtect;
    return STATUS_SUCCESS;
}

NTSTATUS KHelper::Common::CreateUserModeThread(HANDLE process, PVOID startAddr, PVOID parameter, bool createSuspended, OUT PHANDLE threadHandle, OUT PCLIENT_ID clientID)
{
    return RtlCreateUserThread(process, NULL, createSuspended, 0, NULL, NULL, startAddr, parameter, threadHandle, clientID);
}

struct _SendHandleAcessParam
{
    HANDLE handleValue;
    UINT32 newAccess;
    UINT32 oldAccess;
    bool queryOnly;
};

BOOLEAN SendHandleAccessCallback(
#if !defined(_WIN7_)
    IN PHANDLE_TABLE HandleTable,
#endif
    IN PHANDLE_TABLE_ENTRY HandleTableEntry,
    IN HANDLE Handle,
    IN PVOID EnumParameter
)
{
    BOOLEAN ret = FALSE;
    _SendHandleAcessParam* param = (_SendHandleAcessParam*)EnumParameter;

    if (Handle == (HANDLE)param->handleValue)
    {
        if (ExpIsValidObjectEntry(HandleTableEntry))
        {
            // Update access
            param->oldAccess = HandleTableEntry->GrantedAccessBits;
            if (!param->queryOnly) HandleTableEntry->GrantedAccessBits = param->newAccess;
            ret = TRUE;
        }
    }

#if !defined(_WIN7_)
    // Release implicit locks
    _InterlockedExchangeAdd8((char*)&HandleTableEntry->VolatileLowValue, 1);  // Set Unlocked flag to 1
    if (HandleTable != NULL && HandleTable->HandleContentionEvent)
        ExfUnblockPushLock(&HandleTable->HandleContentionEvent, NULL);
#endif

    return ret;
}

NTSTATUS KHelper::Common::SetUserHandleAccess(PEPROCESS process, HANDLE handle, IN OUT UINT32* access, bool queryOnly)
{
    if (UnDocumentedData::EPROCESS_ObjectTable_Offset == UnDocumentedData::INVALID_DATA_VALUE)
    {
        return STATUS_NOT_IMPLEMENTED;
    }

    _SendHandleAcessParam param = {};
    param.handleValue = handle;
    param.queryOnly = queryOnly;
    if (!queryOnly) param.newAccess = *access;

    PHANDLE_TABLE handleTable = *(PHANDLE_TABLE*)((UINT8*)process + UnDocumentedData::EPROCESS_ObjectTable_Offset);
    if (!ExEnumHandleTable(handleTable, SendHandleAccessCallback, &param, 0))
    {
        return STATUS_NOT_FOUND;
    }

    *access = param.oldAccess;
    return STATUS_SUCCESS;
}

NTSTATUS KHelper::Common::DeleteFile1(PUNICODE_STRING fileName)
{
    HANDLE FileHandle = 0;
    PFILE_OBJECT FileObject = 0;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    do
    {
        PIRP Irp = 0;
        IO_STATUS_BLOCK FileIoStatus = {};
        OBJECT_ATTRIBUTES ObjectAttributes = {};
        InitializeObjectAttributes(&ObjectAttributes, fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
        Status = ZwCreateFile(&FileHandle, SYNCHRONIZE | DELETE, &ObjectAttributes, &FileIoStatus, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
        if (!NT_SUCCESS(Status))
            break;

        Status = ObReferenceObjectByHandle(FileHandle, DELETE, *IoFileObjectType, KernelMode, (PVOID*)&FileObject, nullptr);
        if (!NT_SUCCESS(Status))
            break;

        PDEVICE_OBJECT DeviceObject = IoGetRelatedDeviceObject(FileObject);
        Irp = IoAllocateIrp(DeviceObject->StackSize, TRUE);
        if (!Irp)
        {
            Status = STATUS_UNSUCCESSFUL;
            break;
        }

        KEVENT kEvent = {};
        KeInitializeEvent(&kEvent, SynchronizationEvent, FALSE);

        FILE_DISPOSITION_INFORMATION  FileInformation = {};
        FileInformation.DeleteFile = TRUE;

        IO_STATUS_BLOCK IrpIoStatus = {};
        Irp->AssociatedIrp.SystemBuffer = &FileInformation;
        Irp->UserEvent = &kEvent;
        Irp->UserIosb = &IrpIoStatus;
        Irp->Tail.Overlay.OriginalFileObject = FileObject;
        Irp->Tail.Overlay.Thread = (PETHREAD)KeGetCurrentThread();
        Irp->RequestorMode = KernelMode;

        PIO_STACK_LOCATION IrpSp = {};
        IrpSp = IoGetNextIrpStackLocation(Irp);
        IrpSp->MajorFunction = IRP_MJ_SET_INFORMATION;
        IrpSp->DeviceObject = DeviceObject;
        IrpSp->FileObject = FileObject;
        IrpSp->Parameters.SetFile.Length = sizeof(FILE_DISPOSITION_INFORMATION);
        IrpSp->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
        IrpSp->Parameters.SetFile.FileObject = FileObject;
        IoSetCompletionRoutine(Irp, [](PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)->NTSTATUS {
            UNREFERENCED_PARAMETER(DeviceObject);
            UNREFERENCED_PARAMETER(Context);

            Irp->UserIosb->Status = Irp->IoStatus.Status;
            Irp->UserIosb->Information = Irp->IoStatus.Information;
            KeSetEvent(Irp->UserEvent, IO_NO_INCREMENT, FALSE);
            IoFreeIrp(Irp);
            return STATUS_MORE_PROCESSING_REQUIRED;
            }, &kEvent, TRUE, TRUE, TRUE);

        if (FileObject->SectionObjectPointer)
        {
            FileObject->SectionObjectPointer->ImageSectionObject = 0;
            FileObject->SectionObjectPointer->DataSectionObject = 0;
        }

        Status = IoCallDriver(DeviceObject, Irp);
        if (NT_SUCCESS(Status))
        {
            KeWaitForSingleObject(&kEvent, Executive, KernelMode, TRUE, nullptr);
        }
    } while (0);

    if (FileObject) ObfDereferenceObject(FileObject);
    if (FileHandle) ZwClose(FileHandle);

    return Status;
}

// rewrite from git https://github.com/DragonQuestHero/Kernel-Force-Delete
NTSTATUS KHelper::Common::DeleteFile2(PUNICODE_STRING filePath)
{
    NTSTATUS result = STATUS_UNSUCCESSFUL;

    //switch context to UserMode
    PEPROCESS eproc = IoGetCurrentProcess();
    KeAttachProcess(eproc);

    FILE_OBJECT* object = 0;
    HANDLE fileHandle = 0;
    do
    {
        OBJECT_ATTRIBUTES fileObject = {};
        InitializeObjectAttributes(&fileObject,
            filePath,
            OBJ_CASE_INSENSITIVE,
            NULL,
            NULL);

        IO_STATUS_BLOCK ioBlock = {};
        DEVICE_OBJECT* device_object = 0;
        if (!NT_SUCCESS(IoCreateFileSpecifyDeviceObjectHint(
            &fileHandle,
            SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA, //0x100181 
            &fileObject,
            &ioBlock,
            0,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, //FILE_SHARE_VALID_FLAGS,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,//0x60,
            0,
            0,
            CreateFileTypeNone,
            0,
            IO_IGNORE_SHARE_ACCESS_CHECK,
            device_object)))
        {
            break;
        }
  
        if (!NT_SUCCESS(ObReferenceObjectByHandle(fileHandle, 0, 0, 0, (void**)&object, 0)))
        {
            break;
        }

        object->SectionObjectPointer->ImageSectionObject = 0;
        object->DeleteAccess = 1;
        if (!NT_SUCCESS(ZwDeleteFile(&fileObject)))
        {
            break;
        }

        result = STATUS_SUCCESS;

    } while (0);
    
    if (object) ObDereferenceObject(object);
    if (fileHandle) ZwClose(fileHandle);

    KeDetachProcess();
    return result;
}

NTSTATUS KHelper::Common::SetDSE(IN OUT DWORD* value, bool queryOnly)
{
    if (UnDocumentedData::DriverSignatureEnforcement_Offset == UnDocumentedData::INVALID_DATA_VALUE)
    {
        return STATUS_UNSUCCESSFUL;
    }

    RTL_OSVERSIONINFOW info = {};
    info.dwOSVersionInfoSize = sizeof(info);
    RtlGetVersion(&info);

    char* base = 0;
    if (info.dwMajorVersion > 6 || (info.dwMajorVersion == 6 && info.dwMinorVersion > 1))   // win 8 or later
    {
        base = (char*)KHelper::Common::GetModuleBaseAddress64A("CI.DLL");

    }
    else
    {
        ;
    }
    if (!base)
    {
        return STATUS_UNSUCCESSFUL;
    }

    auto dseField = (DWORD*)(base + UnDocumentedData::DriverSignatureEnforcement_Offset);
    auto oldValue = *dseField;
    if (!queryOnly)
    {
        *dseField = *value;
    }
    *value = oldValue;
    return STATUS_SUCCESS;
}
