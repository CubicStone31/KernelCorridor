#include "KC_usermode.h"
#include <windows.h>
#include "../KernelCorridor/interface.h"

HANDLE G_Driver = INVALID_HANDLE_VALUE;
uint32_t DriverReferenceCount = 0;

bool KernelCorridor::LoadDriver(const char* driver_file_path, const char* kernel_service_name)
{
    return false;
}

bool KernelCorridor::DeleteDriver(const char* kernel_service_name)
{
    return false;
}

bool KernelCorridor::Open()
{
    G_Driver = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == G_Driver)
    {
        return false;
    }
    DriverReferenceCount += 1;
    return true;
}

void KernelCorridor::Close()
{
    if (DriverReferenceCount)
    {
        DriverReferenceCount -= 1;
        if (!DriverReferenceCount)
        {
            CloseHandle(G_Driver);
            G_Driver = INVALID_HANDLE_VALUE;
        }
    }
}

bool KernelCorridor::WriteProcessMemory(uint32_t pid, uint64_t address_to_write, const std::vector<uint8_t>& data)
{
    KCProtocols::REQUEST_WRITE_PROCESS_MEM* request = (KCProtocols::REQUEST_WRITE_PROCESS_MEM*)malloc(sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + data.size());
    request->addr = address_to_write;
    request->method = KCProtocols::MEM_ACCESS_METHOD::MapToKernelByMdl;
    request->pid = pid;
    request->size = data.size();
    memcpy(request->data, &data[0], data.size());
    KCProtocols::RESPONSE_WRITE_PROCESS_MEM response = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_WRITE_PROCESS_MEM, request, sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + data.size(), &response, sizeof(response), &bytesReturned, 0))
    {
        return false;
    }
    return true;
}

bool KernelCorridor::ReadProcessMemory(uint32_t pid, uint64_t address_to_read, uint32_t length_to_read, std::vector<uint8_t>& out)
{
    KCProtocols::REQUEST_READ_PROCESS_MEM request = {};
    request.pid = pid;
    request.addr = address_to_read;
    request.size = length_to_read;
    request.method = KCProtocols::MEM_ACCESS_METHOD::MapToKernelByMdl;
    KCProtocols::RESPONSE_READ_PROCESS_MEM* response = (KCProtocols::RESPONSE_READ_PROCESS_MEM*)malloc(sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + length_to_read);
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_READ_PROCESS_MEM, &request, sizeof(request), response, sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + length_to_read, &bytesReturned, 0))
    {
        return false;
    }
    return true;
}
