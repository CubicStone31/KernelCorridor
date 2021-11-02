#pragma once

#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>

#define KHELPERTAG 'LEHK'
#define kprintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#ifdef _DEBUG
#define dprintf(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __VA_ARGS__)
#else
#define dprintf(...) 
#endif // _DEBUG

namespace KHelper
{
    namespace UnDocumentedData
    {
        constexpr UINT32 INVALID_DATA_VALUE = 0xffffffff;

        extern UINT32 EPROCESS_ImageFileName_Offset;
        extern UINT32 EPROCESS_Protection_Offset;
        extern UINT32 EPROCESS_ObjectTable_Offset;
        extern UINT32 DriverSignatureEnforcement_Offset;
    }

    namespace String
    {
        inline void StringToUpperA(char* src, char* dst)
        {
            size_t i;
            for (i = 0; i < strlen(src); i++) {
                dst[i] = (char)toupper(src[i]);
            }
            dst[i] = 0;
        }

        inline char* FindSubStringCaseInsensitiveA(char* src, char* dst)
        {
            size_t src_len = strlen(src);
            size_t dst_len = strlen(dst);
            if (src_len > 4096 || dst_len > 4096)
            {
                return (char*)0;
            }
            PVOID src_pool = ExAllocatePool(NonPagedPool, src_len + 1);
            PVOID dst_pool = ExAllocatePool(NonPagedPool, dst_len + 1);
            StringToUpperA(src, (char*)src_pool);
            StringToUpperA(dst, (char*)dst_pool);
            char* ret = strstr((char*)src_pool, (char*)dst_pool);
            ExFreePool(src_pool);
            ExFreePool(dst_pool);
            return ret == 0 ? ret : ret - (char*)src_pool + src;
        }

        inline bool RtlUnicodeStringContains(PUNICODE_STRING Str, PUNICODE_STRING SubStr, bool CaseInsensitive)
        {
            if (Str == 0 || SubStr == 0 || Str->Length < SubStr->Length)
                return false;

            const USHORT numCharsDiff = (Str->Length - SubStr->Length) / sizeof(WCHAR);
            UNICODE_STRING slice = *Str;
            slice.Length = SubStr->Length;

            for (USHORT i = 0; i <= numCharsDiff; ++i, ++slice.Buffer, slice.MaximumLength -= sizeof(WCHAR))
            {
                if (RtlEqualUnicodeString(&slice, SubStr, CaseInsensitive))
                    return true;
            }
            return false;
        }

        inline bool ByteArrayToStringA(PVOID addr, UINT32 len, char* out, UINT32 outLen)
        {
            UINT8* data = (UINT8*)addr;
            for (UINT32 i = 0; i < len; i++)
            {
                if (!RtlStringCbPrintfA(out + (i * 3), outLen - (i * 3), "%02X ", data[i]))
                {
                    return false;
                }
            }
            return true;
        }
    }

    namespace Common
    {
        extern PDEVICE_OBJECT Device;
        extern UNICODE_STRING DeviceName;
        extern UNICODE_STRING SymLinkName;
        extern bool VirtualDeviceCreated;

        inline bool FindProcessNameOffset() 
        {
            PEPROCESS curproc;
            UINT32 procNameOffset;
            curproc = PsGetCurrentProcess();
            for (int i = 0; i < 4096; i++)
            {
                if (!strncmp("System", (PCHAR)curproc + i, strlen("System")))
                {
                    procNameOffset = i;
                    KHelper::UnDocumentedData::EPROCESS_ImageFileName_Offset = procNameOffset;
                    return true;
                }
            }
            return false;
        }

        inline NTSTATUS GetProcessName(PCHAR theName, UINT32 len)
        {
            if (KHelper::UnDocumentedData::EPROCESS_ImageFileName_Offset == KHelper::UnDocumentedData::INVALID_DATA_VALUE)
            {
                return STATUS_NOT_IMPLEMENTED;
            }

            PEPROCESS curproc;
            char* nameptr;
            curproc = PsGetCurrentProcess();
            nameptr = (PCHAR)curproc + KHelper::UnDocumentedData::EPROCESS_ImageFileName_Offset;
            strncpy(theName, nameptr, len - 1);
            theName[len - 1] = 0; /**//* NULL at end */
            return STATUS_SUCCESS;
        }

        inline KIRQL WPOFFx64()
        {
            KIRQL  irql = KeRaiseIrqlToDpcLevel();
            UINT64  cr0 = __readcr0();
            cr0 &= 0xfffffffffffeffff;
            __writecr0(cr0);
            _disable();
            return  irql;
        }

        inline void WPONx64(KIRQL irql)
        {
            UINT64  cr0 = __readcr0();
            cr0 |= 0x10000;
            _enable();
            __writecr0(cr0);
            KeLowerIrql(irql);
        }

        inline bool IsUserModeAddress(PVOID addr)
        {
            if (addr <= MmHighestUserAddress)
            {
                return true;
            }
            return false;
        }

        PVOID GetModuleBaseAddress64A(char* module_name);

        PVOID KernelGetProcAddress(PVOID ModuleBase, PCHAR pFunctionName);
    
        inline NTSTATUS CreateVirtualDevice(PDRIVER_OBJECT driverObject, const wchar_t* deviceName, const wchar_t* symbolicLinkName)
        {
            RtlInitUnicodeString(&DeviceName, deviceName);

            NTSTATUS status = IoCreateDevice(driverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, 0, &Device);
            if (!NT_SUCCESS(status)) 
            {
                return status;
            }

            RtlInitUnicodeString(&SymLinkName, symbolicLinkName);
            status = IoCreateSymbolicLink(&SymLinkName, &DeviceName);
            if (!NT_SUCCESS(status)) 
            {
                IoDeleteDevice(Device);
                return status;
            }

            VirtualDeviceCreated = true;
            Device->Flags |= DO_BUFFERED_IO;
            return STATUS_SUCCESS;
        }

        inline NTSTATUS DeleteVirtualDevice() 
        {
            if (VirtualDeviceCreated)
            {
                IoDeleteSymbolicLink(&SymLinkName);
                IoDeleteDevice(Device);
                VirtualDeviceCreated = false;
            }
            return STATUS_SUCCESS;
        }

        // Backed by undocumented api MmCopyVirtualMemory(), may fail when target memory page has special memory protection options.
        NTSTATUS ReadProcessMemory(PEPROCESS process, PVOID sourceAddr, PVOID targetAddr, SIZE_T size, SIZE_T* returnedSize);

        // Backed by undocumented api MmCopyVirtualMemory(), may fail when target memory page has special memory protection options.
        NTSTATUS WriteProcessMemory(PEPROCESS process, PVOID targetAddr, PVOID sourceAddr, SIZE_T size, SIZE_T* sizeWritten);

        NTSTATUS ReadProcessMemoryByMdl(PEPROCESS process, PVOID sourceAddr, PVOID targetAddr, SIZE_T size, SIZE_T* returnedSize);

        NTSTATUS WriteProcessMemoryByMdl(PEPROCESS process, PVOID targetAddr, PVOID sourceAddr, SIZE_T size, SIZE_T* sizeWritten);

        NTSTATUS CreateUserModeThread(HANDLE process, PVOID startAddr, PVOID parameter, bool createSuspended, OUT PHANDLE threadHandle, OUT PCLIENT_ID clientID);

        NTSTATUS SetProcessProtectionField(PEPROCESS process, IN OUT UINT8* protect, bool queryOnly);

        NTSTATUS SetUserHandleAccess(PEPROCESS process, HANDLE handle, IN OUT UINT32* access, bool queryOnly);

        NTSTATUS DeleteFile1(PUNICODE_STRING filePath);

        NTSTATUS DeleteFile2(PUNICODE_STRING filePath);

        inline void BSOD()
        {
            __debugbreak();
        }

        NTSTATUS SetDSE(IN OUT DWORD* value, bool queryOnly);

        NTSTATUS QueueUserAPC(PKTHREAD thread, void* addr, void* param, bool forceExecute);

        NTSTATUS SetInformationProcess(HANDLE process, PROCESSINFOCLASS processInformationClass, PVOID processInformation, ULONG processInformationLength);
    };
}













