#include <ntifs.h>
#include "khelper/khelper.h"
#include "../KC_usermode/interface.h"

extern NTSTATUS IRPDispatch(PDRIVER_OBJECT device, PIRP pIrp);

extern "C"
{
    void DriverUnload(PDRIVER_OBJECT DriverObject) 
    {
        UNREFERENCED_PARAMETER(DriverObject);

        KHelper::Common::DeleteVirtualDevice();
    }

    NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
    {
        kprintf("driver entry!\n");
        UNREFERENCED_PARAMETER(RegistryPath);

        KHelper::Common::FindProcessNameOffset();

        auto status = KHelper::Common::CreateVirtualDevice(DriverObject, KC_DEVICE_NAME, KC_SYMBOLIC_NAME);
        if (status)
        {
            kprintf("Failed to create virtual device, error code: %d\n", status);
            return STATUS_UNSUCCESSFUL;
        }

        DriverObject->DriverUnload = DriverUnload;
        for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) 
        {
            DriverObject->MajorFunction[i] = (PDRIVER_DISPATCH)IRPDispatch;
        }

        return STATUS_SUCCESS;;
    }
}
