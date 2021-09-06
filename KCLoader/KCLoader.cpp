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

void OutputMsgW(const wchar_t* fmt, ...)
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
        OutputMsgW(L"Error: no kernel file found.");
        return {};
    }

    if (numOfKernelFilesFound > 1)
    {
        OutputMsgW(L"Error: multiple kernel files found.");
        return {};
    }

    return kernelFilePath;
}

void InstallDriver(const wchar_t* lpszDriverName, const wchar_t* lpszDriverPath) 
{
    wchar_t szTempStr[MAX_PATH];
    HKEY hKey;
    DWORD dwData;
    wchar_t szDriverImagePath[MAX_PATH];

    if (NULL == lpszDriverName || NULL == lpszDriverPath) 
    {
        throw std::exception("Invalid parameter.");
    }
    //得到完整的驱动路径
    GetFullPathNameW(lpszDriverPath, MAX_PATH, szDriverImagePath, NULL);

    SC_HANDLE hServiceMgr = NULL;// SCM管理器的句柄
    SC_HANDLE hService = NULL;// NT驱动程序的服务句柄

    //打开服务控制管理器
    hServiceMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hServiceMgr == NULL) 
    {
        char tmp[256];
        sprintf_s(tmp, "OpenSCManager() failed with %#X.", GetLastError());
        throw std::exception(tmp);
    }

    // OpenSCManager成功

    //创建驱动所对应的服务
    hService = CreateServiceW(hServiceMgr,
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

    if (hService == NULL)
    {
        if (GetLastError() == ERROR_SERVICE_EXISTS)
        {
            //服务创建失败，是由于服务已经创立过
            // delete it, and re-create, as the path to executable may not be correct
            auto prev_service = OpenService(hServiceMgr, lpszDriverName, SERVICE_ALL_ACCESS);
            if (NULL == prev_service)
            {
                CloseServiceHandle(hServiceMgr);
                throw std::exception("Failed to delete previous service: cannot open this service.");
            }
            SERVICE_STATUS_PROCESS status = {};
            DWORD bytesNeeded = 0;
            if (!QueryServiceStatusEx(prev_service, SC_STATUS_PROCESS_INFO, (BYTE*)&status, sizeof(status), &bytesNeeded))
            {
                DWORD error = GetLastError();
                CloseServiceHandle(hServiceMgr);
                CloseServiceHandle(prev_service);
                char tmp[256];
                sprintf_s(tmp, "Failed to query previous service status, QueryServiceStatusEx() failed with %#X.", error);
                throw std::exception(tmp);
            }
            if (status.dwCurrentState != SERVICE_STOPPED)
            {
                CloseServiceHandle(hServiceMgr);
                CloseServiceHandle(prev_service);
                throw std::exception("Previous service is not stopped.");
            }
            if (!DeleteService(prev_service))
            {
                DWORD error = GetLastError();
                CloseServiceHandle(hServiceMgr);
                CloseServiceHandle(prev_service);
                char tmp[256];
                sprintf_s(tmp, "Failed to delete previous service, DeleteService() failed with %#X.", error);
                throw std::exception(tmp);
            }
            CloseServiceHandle(prev_service);

            // the previous service has been deleted, create our service again

            hService = CreateServiceW(hServiceMgr,
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
            if (hService == NULL)
            {
                auto err = GetLastError();
                CloseServiceHandle(hServiceMgr); // SCM句柄
                char tmp[256];
                sprintf_s(tmp, "Second call to CreateServiceW() failed with %#X.", err);
                throw std::exception(tmp);
            }

            CloseServiceHandle(hService);
            CloseServiceHandle(hServiceMgr);
            return;
        }
        else
        {
            auto err = GetLastError();
            CloseServiceHandle(hServiceMgr); // SCM句柄
            char tmp[256];
            sprintf_s(tmp, "CreateServiceW() failed with %#X.", err);
            throw std::exception(tmp);
        }
    }
    CloseServiceHandle(hService); // 服务句柄
    CloseServiceHandle(hServiceMgr); // SCM句柄
    return;
}

void StartDriver(const wchar_t* lpszDriverName)
{
    SC_HANDLE schManager;
    SC_HANDLE schService;
    SERVICE_STATUS svcStatus;

    if (NULL == lpszDriverName) 
    {
        throw std::exception("Invalid parameter.");
    }

    schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schManager)
    {
        char tmp[256];
        sprintf_s(tmp, "OpenSCManager() failed with %#X.", GetLastError());
        throw std::exception(tmp);
    }

    schService = OpenService(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
    if (NULL == schService) 
    {
        auto err = GetLastError();
        CloseServiceHandle(schManager);
        char tmp[256];
        sprintf_s(tmp, "OpenService() failed with %#X.", err);
        throw std::exception(tmp);
    }

    if (!StartService(schService, 0, NULL)) 
    {
        DWORD err = GetLastError();
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);

        if (err == ERROR_SERVICE_ALREADY_RUNNING) 
        {
            return;
        }
        char tmp[256];
        sprintf_s(tmp, "StartService() failed with %#X.", GetLastError());
        throw std::exception(tmp);
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);
    return;
}

bool StopDriver(const wchar_t* lpszDriverName) 
{
    SC_HANDLE schManager;
    SC_HANDLE schService;
    SERVICE_STATUS svcStatus;
    bool bStopped = false;

    schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schManager) {
        return false;
    }

    schService = OpenService(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        CloseServiceHandle(schManager);
        return false;
    }

    if (!ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus) && (svcStatus.dwCurrentState != SERVICE_STOPPED)) {
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        return false;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);

    return true;
}

bool DeleteDriverService(const wchar_t* lpszDriverName) 
{
    SC_HANDLE schManager;
    SC_HANDLE schService;
    SERVICE_STATUS svcStatus;

    schManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schManager) {
        return false;
    }

    schService = OpenService(schManager, lpszDriverName, SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        CloseServiceHandle(schManager);
        return false;
    }

    ControlService(schService, SERVICE_CONTROL_STOP, &svcStatus);
    if (!DeleteService(schService)) {
        CloseServiceHandle(schService);
        CloseServiceHandle(schManager);
        return false;
    }

    CloseServiceHandle(schService);
    CloseServiceHandle(schManager);

    return true;
}

bool UnloadKernelCorridor()
{
    if (!StopDriver(L"KernelCorridor") || !DeleteDriverService(L"KernelCorridor"))
    {
        OutputMsgW(L"Failed to stop driver.");
        return false;
    }
    OutputMsgW(L"Driver stopped.");
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
        InstallDriver(L"KernelCorridor", L".\\KernelCorridor.sys");
        StartDriver(L"KernelCorridor");
    }
    catch (std::exception e)
    {
        OutputMsgW(L"Failed to load driver:");
        OutputMsgW(StringToWString(e.what()).c_str());
        return false;
    }
    OutputMsgW(L"Driver loaded.");
    

    if (!init_symbols)
    {
        OutputMsgW(L"[!] skip loading symbol files, the driver is not fully-initialized.");
        return true;
    }

    // Initialize the driver
    HANDLE driver = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == driver)
    {
        OutputMsgW(L"Cannot open driver.");
        return false;
    }

    auto kernelFilePath = FindKernelExecutable();
    if (!kernelFilePath.size())
    {
        OutputMsgW(L"Error: cannot identify kernel, abort.");
        return false;
    }

    bool win8OrLater = IsWindows8OrGreater();
    auto ciPath = (GetSystemRoot() / "system32" / "ci.dll").wstring();
    try
    {
        OutputMsgW(L"Start downloading pdb for file %ws", kernelFilePath.c_str());
        PDBReader::COINIT(COINIT_APARTMENTTHREADED);
        PDBReader::DownloadPDBForFile(kernelFilePath.c_str(), L"Symbols");

        if (win8OrLater)
        {           
            OutputMsgW(L"Start downloading pdb for file %ws", ciPath.c_str());
            PDBReader::DownloadPDBForFile(ciPath.c_str(), L"Symbols");
        }
        OutputMsgW(L"Download pdb succeeded.");

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
                OutputMsgW(L"Warning: Failed to load critical data. Code: %d.", type);
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

        OutputMsgW(L"Driver initialized successfully.");
        return true;
    }
    catch (std::exception e)
    {
        OutputMsgW(StringToWString(e.what()).c_str());
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
        OutputMsgW(L"usage: \nkcloader.exe load [--no-symbol]\nkcloader unload");
    }

    return 0;
}


