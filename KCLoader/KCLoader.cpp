// KCLoader.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <filesystem>
#include "PDBReader/PDBReader.h"
#include "../KernelCorridor/interface.h"
#include <list>
#include <utility>
#include <versionhelpers.h>
#include <string>
#include <memory>

void PrintW(const wchar_t* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int len = _vscwprintf(fmt, args) + 1;
    wchar_t* lpszBuf = (TCHAR*)_alloca(len * sizeof(wchar_t));
    vswprintf_s(lpszBuf, len, fmt, args);
    va_end(args);    
    printf("%ws\n", lpszBuf);
    return;
}

/// <summary>
/// Caution: memory leak in this function
/// </summary>
/// <param name="fmt"></param>
/// <param name=""></param>
void ThrowException(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int len = _vscprintf(fmt, args) + 1;
    static char* buffer = (char*)malloc(1024 * 1024);
    vsprintf_s(buffer, len, fmt, args);
    va_end(args);
    throw std::exception(buffer);
}

class ServiceHolder
{
public:
    ServiceHolder(SC_HANDLE handle)
    {
        this->handle = handle;
    }

    ~ServiceHolder()
    {
        CloseServiceHandle(handle);
    }
private:
    SC_HANDLE handle;
};

std::wstring StringToWString(const std::string& str)
{
    int num = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    wchar_t* wide = new wchar_t[num];
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wide, num);
    std::wstring w_str(wide);
    delete[] wide;
    return w_str;
}

// Todo: a more robust way for get systemroot
std::filesystem::path GetSystemRoot()
{
    return "C:\\Windows";
}

std::wstring FindKernelExecutable()
{
    std::filesystem::path systemPath = GetSystemRoot() / "System32";
    std::filesystem::path possibleFiles[] = { "ntoskrnl.exe", "ntkrnlmp.exe", "ntkrnlpa.exe",  "ntkrpamp.exe" };
    int numOfKernelFilesFound = 0;
    std::wstring kernelFilePath ;

    for (const auto& p : possibleFiles)
    {
        if (std::filesystem::is_regular_file(systemPath / p))
        {
            numOfKernelFilesFound += 1;
            kernelFilePath = (systemPath / p).wstring();
        }
    }

    if (!numOfKernelFilesFound)
    {
        PrintW(L"Error: no kernel file found.");
        return {};
    }

    if (numOfKernelFilesFound > 1)
    {
        PrintW(L"Error: multiple kernel files found.");
        return {};
    }

    return kernelFilePath;
}

/// <summary>
/// Install driver service
/// </summary>
/// <param name="lpszDriverName"></param>
/// <param name="lpszDriverPath"></param>
/// <returns>return false if a service with the same name exists. return true if no error occurs</returns>
bool InstallDriver(const wchar_t* lpszDriverName, const wchar_t* lpszDriverPath) 
{
    wchar_t szDriverImagePath[MAX_PATH];
    GetFullPathNameW(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

    auto serviceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (serviceMgr == NULL) 
    {
        ThrowException("OpenSCManagerW() failed with last error %d.", GetLastError());
    }
    ServiceHolder holder1(serviceMgr);

    auto service = CreateServiceW(serviceMgr,
        lpszDriverName, // 驱动程序的在注册表中的名字
        lpszDriverName, // 注册表驱动程序的DisplayName 值
        SERVICE_ALL_ACCESS, // 加载驱动程序的访问权限
        SERVICE_KERNEL_DRIVER, // 表示加载的服务是文件系统驱动程序
        SERVICE_DEMAND_START, // 注册表驱动程序的Start 值
        SERVICE_ERROR_IGNORE, // 注册表驱动程序的ErrorControl 值
        szDriverImagePath, // 注册表驱动程序的ImagePath 值
        0,// 注册表驱动程序的Group 值
        NULL,
        0, // 注册表驱动程序的DependOnService 值
        NULL,
        NULL);
    if (service == NULL)
    {
        auto error = GetLastError();
        if (error != ERROR_SERVICE_EXISTS)
        {
            ThrowException("CreateServiceW() failed with last error %d.", GetLastError());
        }
        else
        {
            return false;
        }
    }
    ServiceHolder holder2(service);
    return true;
}

void StartDriver(const wchar_t* lpszDriverName)
{
    auto serviceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == serviceMgr)
    {
        ThrowException("OpenSCManager() failed with %d.", GetLastError());
    }
    ServiceHolder holder1(serviceMgr);
    auto service = OpenServiceW(serviceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
    if (NULL == service) 
    {
        ThrowException("OpenService() failed with %d.", GetLastError());
    }
    ServiceHolder holder2(service);

    if (!StartServiceW(service, 0, NULL)) 
    {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) 
        {
            ThrowException("StartServiceW() failed with %d.", err);
        }   
    }
    return;
}

void StopDriver(const wchar_t* lpszDriverName) 
{
    auto serviceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == serviceMgr)
    {
        ThrowException("OpenSCManagerW() failed with last error %d.", GetLastError());
    }
    ServiceHolder holder1(serviceMgr);
    auto service = OpenServiceW(serviceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
    if (NULL == service) 
    {
        ThrowException("OpenServiceW() failed with last error %d.", GetLastError());
    }
    ServiceHolder holder2(service);


    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &bytesNeeded))
    {
        ThrowException("QueryServiceStatusEx() failed with last error %d.", GetLastError());
    }
    if (status.dwCurrentState == SERVICE_STOPPED)
    {
        return;
    }

    SERVICE_STATUS svcStatus = {};
    if (!ControlService(service, SERVICE_CONTROL_STOP, &svcStatus))
    {
        ThrowException("ControlService() failed with last error %d.", GetLastError());
    }
    if (svcStatus.dwCurrentState != SERVICE_STOPPED)
    {
        ThrowException("Target service is not stopped.");
    }
}

void DeleteDriverService(const wchar_t* lpszDriverName) 
{
    auto serviceMgr = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == serviceMgr)
    {
        ThrowException("OpenSCManagerW() failed with last error %d.", GetLastError());
    }
    ServiceHolder holder1(serviceMgr);

    auto service = OpenServiceW(serviceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
    if (NULL == service) 
    {
        ThrowException("OpenServiceW() failed with last error %d.", GetLastError());
    }
    ServiceHolder holder2(service);

    SERVICE_STATUS_PROCESS status = {};
    DWORD bytesNeeded = 0;
    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &bytesNeeded))
    {
        ThrowException("QueryServiceStatusEx() failed with last error %d.", GetLastError());
    }
    if (status.dwCurrentState != SERVICE_STOPPED)
    {
        ThrowException("Target service is still running.");
    }

    if (!DeleteService(service))
    {
        ThrowException("DeleteService() failed with last error %d.", GetLastError());
    }
    return;
}

bool UnloadKernelCorridor()
{
    try
    {
        StopDriver(L"KernelCorridor");
        DeleteDriverService(L"KernelCorridor");
        PrintW(L"Driver stopped.");
        return true;
    }
    catch (std::exception e)
    {
        PrintW(L"Failed to stop driver:");
        PrintW(StringToWString(e.what()).c_str());
        return false;
    }
    
    return true;
}

std::tuple<bool, PVOID> FindStructMemberOffset(PDBReader* symbolSrc, const wchar_t* structName, const wchar_t* memberName)
{
    auto value = symbolSrc->FindStructMemberOffset(structName, memberName);
    if (value)
    {
        std::tuple<bool, PVOID> ret(true, (PVOID)value.value());
        return ret;
    }
    else
    {
        std::tuple<bool, PVOID> ret(false, NULL);
        return ret;
    }
}

std::tuple<bool, PVOID> FindGlobalSymbolOffset(PDBReader* symbolSrc, const wchar_t* symbolName)
{
    DWORD type = 0;
    auto value = symbolSrc->FindSymbol(symbolName, type);
    if (value)
    {
        std::tuple<bool, PVOID> ret(true, (PVOID)value.value());
        return ret;
    }
    else
    {
        std::tuple<bool, PVOID> ret(false, NULL);
        return ret;
    }
}

bool LoadAndInitKernelCorridor(bool init_symbols)
{
    try
    {
        if (!InstallDriver(L"KernelCorridor", L".\\KernelCorridor.sys"))
        {
            // A service with the same name exists
            StopDriver(L"KernelCorridor");
            DeleteDriverService(L"KernelCorridor");
            if (!InstallDriver(L"KernelCorridor", L".\\KernelCorridor.sys"))
            {
                ThrowException("Second call to InstallDriver() failed.");
            }
        }
        StartDriver(L"KernelCorridor");
    }
    catch (std::exception e)
    {
        PrintW(L"Failed to load driver:");
        PrintW(StringToWString(e.what()).c_str());
        return false;
    }
    PrintW(L"Driver loaded.");
    
    if (!init_symbols)
    {
        PrintW(L"[!] skip loading symbol files, the driver is not fully-initialized.");
        return true;
    }

    // Initialize the driver
    HANDLE driver = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == driver)
    {
        PrintW(L"Cannot open driver.");
        return false;
    }

    auto kernelFilePath = FindKernelExecutable();
    if (!kernelFilePath.size())
    {
        PrintW(L"Error: cannot identify kernel, abort.");
        return false;
    }

    bool win8OrLater = IsWindows8OrGreater();
    auto ciPath = (GetSystemRoot() / "system32" / "ci.dll").wstring();
    try
    {
        PrintW(L"Start downloading pdb for file %ws", kernelFilePath.c_str());
        PDBReader::COINIT(COINIT_APARTMENTTHREADED);
        PDBReader::DownloadPDBForFile(kernelFilePath.c_str(), L"Symbols");

        if (win8OrLater)
        {           
            PrintW(L"Start downloading pdb for file %ws", ciPath.c_str());
            PDBReader::DownloadPDBForFile(ciPath.c_str(), L"Symbols");
        }
        PrintW(L"Download pdb succeeded.");

        PDBReader kernelPDB(kernelFilePath.c_str(), L"Symbols");
        PDBReader ciPDB(ciPath.c_str(), L"Symbols");
        std::list<std::tuple<KCProtocols::UNDOCUMENTED_DATA_TYPE, bool, PVOID>> initData = {};

        initData.push_back(std::tuple_cat(std::make_tuple(KCProtocols::UNDOCUMENTED_DATA_TYPE::EPROCESS_Protection_Offset), FindStructMemberOffset(&kernelPDB, L"_EPROCESS", L"Protection")));
        initData.push_back(std::tuple_cat(std::make_tuple(KCProtocols::UNDOCUMENTED_DATA_TYPE::EPROCESS_ImageFileName_Offset), FindStructMemberOffset(&kernelPDB, L"_EPROCESS", L"ImageFileName")));
        initData.push_back(std::tuple_cat(std::make_tuple(KCProtocols::UNDOCUMENTED_DATA_TYPE::EPROCESS_ObjectTable_Offset), FindStructMemberOffset(&kernelPDB, L"_EPROCESS", L"ObjectTable")));
        if (win8OrLater)
        {
            initData.push_back(std::tuple_cat(std::make_tuple(KCProtocols::UNDOCUMENTED_DATA_TYPE::DriverSignatureEnforcement_Offset), FindGlobalSymbolOffset(&ciPDB, L"g_CiOptions")));
        }
        else
        {
            initData.push_back(std::tuple_cat(std::make_tuple(KCProtocols::UNDOCUMENTED_DATA_TYPE::DriverSignatureEnforcement_Offset), FindGlobalSymbolOffset(&kernelPDB, L"g_CiEnabled")));
        }


        for (const auto& elem : initData)
        {
            auto type = std::get<0>(elem);
            auto value = std::get<2>(elem);
            if (!std::get<1>(elem))
            {
                PrintW(L"Warning: Failed to load critical data. Code: %d.", type);
                continue;
            }

            KCProtocols::REQUEST_INIT_UNDOCUMENTED_DATA request = {};
            request.type = type;
            request.data = value;
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(driver, CC_INIT_UNDOCUMENTED_DATA, &request, sizeof(request), 0, 0, &bytesReturned, 0))
            {
                throw std::exception("Failed to connect to driver.");
                return false;
            }
        }

        PrintW(L"Driver initialized successfully.");
        return true;
    }
    catch (std::exception e)
    {
        PrintW(StringToWString(e.what()).c_str());
        UnloadKernelCorridor();
        return false;
    }

    return true;
}

int main(int argc, char* argv[])
{
    bool commandline_handled = false;

    if (argc >= 2 && !_stricmp(argv[1], "load"))
    {
        if (argc == 3)
        {
            if (!_stricmp(argv[2], "--no-symbol"))
            {
                LoadAndInitKernelCorridor(false);
                commandline_handled = true;
            }
        }
        else if (argc == 2)
        {
            LoadAndInitKernelCorridor(true);
            commandline_handled = true;
        }
    }
    else if (argc >= 2 && !_stricmp(argv[1], "unload"))
    {
        UnloadKernelCorridor();
        commandline_handled = true;
    }

    if (!commandline_handled)
    {
        PrintW(L"usage: \nkcloader.exe load [--no-symbol]\nkcloader unload");
    }

    return 0;
}


