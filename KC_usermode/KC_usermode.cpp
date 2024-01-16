#include "KC_usermode.h"
#include <windows.h>
#include "../KernelCorridor/interface.h"
#include <cstdlib>
#include <time.h>

HANDLE G_Driver = INVALID_HANDLE_VALUE;
uint32_t DriverReferenceCount = 0;

bool KernelCorridor::CreateDriverServiceAndLoadDriver(const std::wstring& driver_file_path, const std::wstring& service_name, bool append_random_suffix, std::wstring& actual_service_name)
{
    DWORD dwAttrib = GetFileAttributesW(driver_file_path.c_str());
    if (dwAttrib == INVALID_FILE_ATTRIBUTES || (dwAttrib & FILE_ATTRIBUTE_DIRECTORY))
    {
        return false;
    }
    auto service_mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (service_mgr == NULL)
    {
        return false;
    }
    if (append_random_suffix)
    {
        srand(time(0));
        auto random_number = rand() & 0xffff;
        actual_service_name = service_name + L"_" + std::to_wstring(random_number);
    }
    else
    {
        actual_service_name = service_name;
    }
    auto service = CreateServiceW(service_mgr,
        actual_service_name.c_str(), 
        actual_service_name.c_str(), 
        SERVICE_ALL_ACCESS, 
        SERVICE_KERNEL_DRIVER, 
        SERVICE_DEMAND_START, 
        SERVICE_ERROR_IGNORE,
        driver_file_path.c_str(), 
        0,
        0,
        0, 
        0,
        0);
    if (!service)
    {
        // maybe a previous service exists
        if (ERROR_SERVICE_EXISTS == GetLastError())
        {
            // try to delete it
            auto previous_service = OpenServiceW(service_mgr, actual_service_name.c_str(), SERVICE_ALL_ACCESS);
            if (!previous_service)
            {
                CloseServiceHandle(service_mgr);
                return false;
            }
            SERVICE_STATUS_PROCESS status = {};
            DWORD bytesNeeded = 0;
            if (!QueryServiceStatusEx(previous_service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &bytesNeeded))
            {
                CloseServiceHandle(previous_service);
                CloseServiceHandle(service_mgr);
                return false;
            }
            if (status.dwCurrentState != SERVICE_STOPPED)
            {
                // still running ? 
                CloseServiceHandle(previous_service);
                CloseServiceHandle(service_mgr);
                return false;
            }
            // so there is a previous registered service, and it is not running now
            // delete it!
            if (!DeleteService(previous_service))
            {
                CloseServiceHandle(previous_service);
                CloseServiceHandle(service_mgr);
                return false;
            }
            CloseServiceHandle(previous_service);
            // now register our new service again
            service = CreateServiceW(service_mgr,
                actual_service_name.c_str(),
                actual_service_name.c_str(),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_IGNORE,
                driver_file_path.c_str(),
                0,
                0,
                0,
                0,
                0);
            if (!service)
            {
                // failed again??
                CloseServiceHandle(service_mgr);
                return false;
            }
        }
        else
        {
            // cannot create a new service, failed
            CloseServiceHandle(service_mgr);
            return false;
        }
    }
    // service registered, start it now
    if (!StartServiceW(service, 0, 0))
    {
        // failed to load driver, delete the newly registered service
        DeleteService(service);
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    // driver loaded successfully
    CloseServiceHandle(service);
    CloseServiceHandle(service_mgr);
    return true;
}

bool KernelCorridor::StopDriverServiceAndDeleteIt(const std::wstring& kernel_service_name)
{
    auto service_mgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!service_mgr)
    {
        return false;
    }
    auto service = OpenServiceW(service_mgr, kernel_service_name.c_str(), SERVICE_ALL_ACCESS);
    if (!service)
    {
        CloseServiceHandle(service_mgr);
        return false;
    }
    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &bytesNeeded))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    if (status.dwCurrentState == SERVICE_STOPPED)
    {
        if (!DeleteService(service))
        {
            CloseServiceHandle(service);
            CloseServiceHandle(service_mgr);
            return false;
        }
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return true;
    }
    SERVICE_STATUS svcStatus = {};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &svcStatus))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    if (svcStatus.dwCurrentState != SERVICE_STOPPED)
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    if (!DeleteService(service))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(service_mgr);
        return false;
    }
    CloseServiceHandle(service);
    CloseServiceHandle(service_mgr);
    return true;
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
