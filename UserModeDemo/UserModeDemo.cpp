// UserModeDemo.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <string>
#include <vector>
#include <iomanip>
#include <tlhelp32.h>
#include <algorithm>
#include <cwctype>
#include <fstream>
#include <tuple>
#include "../KernelCorridor/interface.h"

bool ByteArrayToStringA(PVOID addr, UINT32 len, char* out, UINT32 outLen)
{
    UINT8* data = (UINT8*)addr;
    for (UINT32 i = 0; i < len; i++)
    {
        if (!sprintf_s(out + (i * 3), outLen - (i * 3), "%02X ", data[i]))
        {
            return false;
        }
    }
    return true;
}

std::vector<BYTE> StringToByteArray(const std::string& str)
{
    std::vector<BYTE> data = {};
    std::vector<BYTE> ret = {};

    for (char c : str)
    {
        if (c == ' ' || c == 0)
        {
            continue;
        }

        bool isCharacter = false;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
        {
            isCharacter = true;
        }
        if (!isCharacter)
        {
            return {};
        }

        data.push_back(c);
    }

    if (data.size() % 2)
    {
        return {};
    }

    for (int i = 0; i < data.size(); i += 2)
    {
        char tmp[3];
        tmp[0] = data[i];
        tmp[1] = data[i + 1];
        tmp[2] = 0;

        ret.push_back(std::stoi(tmp, 0, 16));
    }

    return ret;
}

bool FindSubStringCaseInsensitiveW(const std::wstring& dest, const std::wstring& src)
{
    auto it = std::search(
        dest.begin(), dest.end(),
        src.begin(), src.end(),
        [](wchar_t ch1, wchar_t ch2) { return std::towupper(ch1) == std::towupper(ch2); }
    );
    return (it != dest.end());
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

std::tuple<char*, DWORD> GetProcessModule(DWORD pid, const std::wstring& moduleName)
{
    auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE)
    {
        std::cout << "CreateToolhelp32Snapshot() failed with 0x" << GetLastError() << std::endl;
        return {};
    }
    MODULEENTRY32 info = {};
    info.dwSize = sizeof(info);
    if (!Module32First(snap, &info))
    {
        std::cout << "Module32First() failed with 0x" << GetLastError() << std::endl;
        return {};
    }

    do
    {
        if (!_wcsicmp(info.szModule, moduleName.c_str()))
        {
            return std::make_tuple((char*)info.modBaseAddr, info.modBaseSize);
        }
    } while (Module32Next(snap, &info));
    
    return {};
}

HANDLE G_Driver;

void ReadMemory(int argc, char* argv[])
{
    if (argc != 6)
    {
        std::cout << "usage: demo.exe read method pid addr(hex) size\n";
        return;
    }

    try
    {
        KCProtocols::MEM_ACCESS_METHOD method = (KCProtocols::MEM_ACCESS_METHOD)std::stoull(argv[2]);
        DWORD pid = (DWORD)std::stoull(argv[3]);
        PVOID addr = (PVOID)std::stoull(argv[4], 0, 16);
        DWORD size = (DWORD)std::stoull(argv[5]);

        KCProtocols::REQUEST_READ_PROCESS_MEM request = {};
        request.pid = pid;
        request.addr = addr;
        request.size = size;
        request.method = method;
        KCProtocols::RESPONSE_READ_PROCESS_MEM* response = (KCProtocols::RESPONSE_READ_PROCESS_MEM*)malloc(sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + size);

        DWORD bytesReturned = 0;
        if (!DeviceIoControl(G_Driver, CC_READ_PROCESS_MEM, &request, sizeof(request), response, sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + size, &bytesReturned, 0))
        {
            std::cout << "DeviceIOControl Failed.\n";
            return;
        }

        std::cout << "BytesRead: " << response->size << std::endl;
        char* display = (char*)malloc(3 * response->size + 1);
        ByteArrayToStringA(response->data, response->size, display, 3 * response->size + 1);

        std::cout << "Data: " << display << std::endl;
        return;
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
}

void WriteMemory(int argc, char* argv[])
{
    if (argc != 6)
    {
        std::cout << "usage: demo.exe write method pid addr(hex) data\n";
        return;
    }

    try
    {
        KCProtocols::MEM_ACCESS_METHOD method = (KCProtocols::MEM_ACCESS_METHOD)std::stoull(argv[2]);
        DWORD pid = (DWORD)std::stoull(argv[3]);
        PVOID addr = (PVOID)std::stoull(argv[4], 0, 16);
        auto data = StringToByteArray(argv[5]);
        std::cout << "Number of bytes to write: " << data.size() << std::endl;

        KCProtocols::REQUEST_WRITE_PROCESS_MEM* request = (KCProtocols::REQUEST_WRITE_PROCESS_MEM*)malloc(sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + data.size());
        request->addr = addr;
        request->method = method;
        request->pid = pid;
        request->size = data.size();
        memcpy(request->data, &data[0], data.size());
        KCProtocols::RESPONSE_WRITE_PROCESS_MEM response = {};

        DWORD bytesReturned = 0;
        if (!DeviceIoControl(G_Driver, CC_WRITE_PROCESS_MEM, request, sizeof(KCProtocols::REQUEST_WRITE_PROCESS_MEM) + data.size(), &response, sizeof(response), &bytesReturned, 0))
        {
            std::cout << "DeviceIOControl Failed.\n";
            return;
        }

        std::cout << "Bytes written: " << response.bytesWritten << std::endl;
        return;
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
}

void CreateThread(int argc, char* argv[])
{
    if (argc != 5)
    {
        std::cout << "usage: demo.exe createthread pid startAddr param\n";
        return;
    }

    try
    {
        DWORD pid = (DWORD)std::stoull(argv[2]);
        PVOID startAddr = (PVOID)std::stoull(argv[3], 0, 16);
        PVOID param = (PVOID)std::stoull(argv[4], 0, 16);

        KCProtocols::REQUEST_CREATE_USER_THREAD request = {};
        request.createSuspended = false;
        request.parameter = param;
        request.pid = pid;
        request.startAddr = startAddr;
        KCProtocols::RESPONSE_CREATE_USER_THREAD response = {};

        DWORD bytesReturned = 0;
        if (!DeviceIoControl(G_Driver, CC_CREATE_USER_THREAD, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
        {
            std::cout << "DeviceIOControl Failed.\n";
            return;
        }

        std::cout << "Returned pid: " << response.processID << std::endl;
        std::cout << "Returned tid: " << response.threadID << std::endl;
        return;
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
}

void ChangeProtect(int argc, char* argv[])
{
    try
    {
        bool queryOnly = true;
        KCProtocols::REQUEST_SET_PROCESS_PROTECTION_FIELD request = {};
        KCProtocols::RESPONSE_SET_PROCESS_PROTECTION_FIELD response = {};
        if (argc == 3)
        {
            DWORD pid = (DWORD)std::stoull(argv[2]);

            request.pid = pid;
            request.queryOnly = true;
            request.newProtect = 0;

        }
        else if (argc == 4)
        {
            DWORD pid = (DWORD)std::stoull(argv[2]);
            UINT8 newProtect = (UINT8)std::stoull(argv[3]);
            queryOnly = false;

            request.pid = pid;
            request.queryOnly = false;
            request.newProtect = newProtect;
        }
        else
        {
            std::cout << "usage: demo.exe changeprotect pid [newprotect]\n";
            return;
        }

        DWORD bytesReturned = 0;
        if (!DeviceIoControl(G_Driver, CC_SET_PROCESS_PROTECTION_FIELD, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
        {
            std::cout << "DeviceIOControl Failed.\n";
            return;
        }

        if (!queryOnly)
        {
            std::cout << "Set protection succeeds.\n";
            std::cout << "Old protection: " << (DWORD)response.oldProtect << std::endl;
            return;
        }
        else
        {
            std::cout << "Process protection: " << (DWORD)response.oldProtect << std::endl;
            return;
        }
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
}

void ChangeHandleAccess(int argc, char* argv[])
{
    try
    {
        DWORD pid = (DWORD)std::stoull(argv[2]);
        HANDLE handle = (HANDLE)std::stoull(argv[3], 0, 16);
        bool queryOnly;
        DWORD access;
        if (argc == 4)
        {
            queryOnly = true;
            access = 0;
        }
        else if (argc == 5)
        {
            queryOnly = false;
            access = (DWORD)std::stoull(argv[4]);
        }
        else
        {
            std::cout << "usage: demo.exe h pid handle(hex) [access]\n";
            return;
        }

        KCProtocols::REQUEST_SET_HANDLE_ACCESS request = {};
        KCProtocols::RESPONSE_SET_HANDLE_ACCESS response = {};
        request.handle = handle;
        request.newAccess = access;
        request.pid = pid;
        request.queryOnly = queryOnly;

        DWORD bytesReturned = 0;
        if (!DeviceIoControl(G_Driver, CC_SET_HADNLE_ACCESS, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
        {
            std::cout << "DeviceIOControl Failed.\n";
            return;
        }

        if (queryOnly)
        {
            std::cout << "Handle access: " << (DWORD)response.oldAccess << std::endl;
            return;
        }
        else
        {
            std::cout << "Old handle access: " << (DWORD)response.oldAccess << std::endl;
            std::cout << "New handle access: " << (DWORD)request.newAccess << std::endl;
            return;
        }
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
}

void TestReadingProcess(int argc, char* argv[])
{
    // demo.exe te pid 
    if (argc != 3)
    {
        std::cout << "usage: demo.exe te pid\n";
    }

    try
    {
        DWORD pid = (DWORD)std::stoull(argv[2]);

        auto handle = OpenProcess(PROCESS_SET_LIMITED_INFORMATION, 0, pid);
        if (!handle)
        {
            throw std::exception("failed to get a initial handle.");
        }

        std::cout << "Please elevate this handle: 0x" << std::hex << (unsigned long long)handle << std::endl;
        getchar();

        auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
        if (snap == INVALID_HANDLE_VALUE)
        {
            std::cout << "CreateToolhelp32Snapshot() failed with 0x" << GetLastError() << std::endl;
            return;
        }
        MODULEENTRY32 info = {};
        info.dwSize = sizeof(info);
        if (!Module32First(snap, &info))
        {
            std::cout << "Module32First() failed with 0x" << GetLastError() << std::endl;
            return;
        }

        PVOID base = 0;
        do
        {
            if (FindSubStringCaseInsensitiveW(info.szExePath, L".exe"))
            {
                base = info.modBaseAddr;
                break;
            }
        } while (Module32Next(snap, &info));
        if (!base)
        {
            std::cout << "Cannot find main module.\n";
            return;
        }
        std::wcout << "Find main module " << info.szExePath << std::endl;
        std::cout << "Main module base at 0x" << base << std::endl;

        char readData[4];
        if (!ReadProcessMemory(handle, base, readData, sizeof(readData), 0))
        {
            std::cout << "ReadProcessMemory() failed with 0x" << GetLastError() << std::endl;
            return;
        }
        char* display = (char*)malloc(3 * sizeof(readData) + 1);
        ByteArrayToStringA(readData, sizeof(readData), display, 3 * sizeof(readData) + 1);
        std::cout << "Data: " << display << std::endl;
        return;
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
}

void ForceDeleteFile(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cout << "usage: demo.exe d path\n";
        return;
    }

    auto filePath = std::wstring(L"\\??\\") + StringToWString(argv[2]);

    KCProtocols::REQUEST_DELETE_FILE request = {};
    if (wcscpy_s(request.path, filePath.c_str()))
    {
        std::cout << "Error in wcscpy_s, maybe file path too long?\n";
        return;
    }

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_DELETE_FILE, &request, sizeof(request), 0, 0, &bytesReturned, 0))
    {
        std::cout << "DeviceIOControl Failed.\n";
        return;
    }

    std::cout << "Request handled successfully\n";
    return;
}

void DumpProcess(int argc, char* argv[])
{
    if (argc != 5)
    {
        std::cout << "usage: demo.exe du pid -m moduleName\n";
        std::cout << "usage: demo.exe du pid addr(hex) size\n";
        return;
    }

    try
    {
        DWORD pid = (DWORD)std::stoull(argv[2]);
        DWORD bytesRemaining = 0;
        char* curPtr = NULL;
        if (!_stricmp(argv[3], "-m"))
        {
            auto moduleName = StringToWString(argv[4]);
            auto info = GetProcessModule(pid, moduleName);
            if (!std::get<0>(info) || !std::get<1>(info))
            {
                std::cout << "Failed to get module info.\n";
                return;
            }
            curPtr = std::get<0>(info);
            bytesRemaining = std::get<1>(info);
        }
        else
        {
            curPtr = (char*)std::stoull(argv[3], 0, 16);
            bytesRemaining = (DWORD)std::stoull(argv[4]);
        }

        constexpr DWORD trunkSize = 0x1000;
        KCProtocols::REQUEST_READ_PROCESS_MEM request = {};
        KCProtocols::RESPONSE_READ_PROCESS_MEM* response = (KCProtocols::RESPONSE_READ_PROCESS_MEM*)malloc(sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + trunkSize);
        request.method = KCProtocols::MEM_ACCESS_METHOD::MmCopyVirtualMemory;
        request.pid = pid;     
        auto fileName = std::to_string(pid) + ".dump";
        std::ofstream out(fileName, std::ios::binary);
        do
        {
            DWORD bytesToRead = min(trunkSize, bytesRemaining);
            bytesRemaining = bytesRemaining - bytesToRead;
            request.size = bytesToRead;
            request.addr = curPtr;
            curPtr += bytesToRead;

            DWORD bytesReturned = 0;
            if (!DeviceIoControl(G_Driver, CC_READ_PROCESS_MEM, &request, sizeof(request), response, sizeof(KCProtocols::RESPONSE_READ_PROCESS_MEM) + trunkSize, &bytesReturned, 0))
            {
                std::cout << "DeviceIOControl failed.\n";
                return;
            }

            out.write((const char*)response->data, response->size);

        } while (bytesRemaining);

        out.close();
        std::cout << "Memory dump saved to " << fileName.c_str() << std::endl;
        return;
    }
    catch (std::exception e)
    {
        std::cout << e.what() << std::endl;
        return;
    }
}

void TriggerBSOD(int argc, char* argv[])
{
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_BSOD, 0, 0, 0, 0, &bytesReturned, 0))
    {
        std::cout << "DeviceIOControl failed.\n";
        return;
    }

    std::cout << "Everything seems fine...\n";
    return;
}

void SetDSE(int argc, char* argv[])
{
    if (argc != 2 && argc != 3)
    {
        std::cout << "usage: demo.exe dse [newvalue]\nYou may want to set it to zero to disable driver signature check. Don't forget to turn it back on when you have loaded your unsigned driver.";
        return;
    }

    DWORD newDseValue = 0;
    bool queryOnly = true;
    if (argc == 3)
    {
        queryOnly = false;
        try
        {
            newDseValue = (DWORD)std::stoull(argv[2]);
        }
        catch (std::exception e)
        {
            std::cout << e.what() << std::endl;
            return;
        }
    }

    KCProtocols::REQUEST_SET_DSE request = {};
    KCProtocols::RESPONSE_SET_DSE response = {};
    request.queryOnly = queryOnly;
    request.value = newDseValue;

    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_SET_DSE, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        std::cout << "DeviceIOControl failed.\n";
        return;
    }

    if (queryOnly)
    {
        std::cout << "Driver signature enforcement value: " << response.oldValue << std::endl;
        return;
    }
    else
    {
        std::cout << "Old DSE value: " << response.oldValue << std::endl;
        std::cout << "New DSE value: " << request.value << std::endl;
        return;
    }
}

void Wait(int argc, char* argv[])
{
    Sleep(INFINITE);
}

void usage()
{
    std::cout << "usage: demo.exe [r]ead/[w]rite/create[T]hread/change[P]rotect/change[H]andleAccess/[te]stReadingProcess/[d]eleteFile/[du]mpProcess/[bs]od/set[DSE]/[wa]it\n";
}

int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        usage();
        return 0;
    }

    G_Driver = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == G_Driver)
    {
        std::cout << "Cannot open driver.\n";
        return 0;
    }

    if (!_stricmp(argv[1], "r") || !_stricmp(argv[1], "read"))
    {
        ReadMemory(argc, argv);
    }
    else if (!_stricmp(argv[1], "w") || !_stricmp(argv[1], "write"))
    {
        WriteMemory(argc, argv);
    }
    else if (!_stricmp(argv[1], "t") || !_stricmp(argv[1], "createThread"))
    {
        CreateThread(argc, argv);
    }
    else if (!_stricmp(argv[1], "p") || !_stricmp(argv[1], "changeProtect"))
    {
        ChangeProtect(argc, argv);
    }
    else if (!_stricmp(argv[1], "h") || !_stricmp(argv[1], "changeHandleAccess"))
    {
        ChangeHandleAccess(argc, argv);
    }
    else if (!_stricmp(argv[1], "te") || !_stricmp(argv[1], "testReadingProcess"))
    {
        TestReadingProcess(argc, argv);
    }
    else if (!_stricmp(argv[1], "d") || !_stricmp(argv[1], "deleteFile"))
    {
        ForceDeleteFile(argc, argv);
    }
    else if (!_stricmp(argv[1], "du") || !_stricmp(argv[1], "dumpProcess"))
    {
        DumpProcess(argc, argv);
    }
    else if (!_stricmp(argv[1], "bs") || !_stricmp(argv[1], "bsod"))
    {
        TriggerBSOD(argc, argv);
    }
    else if (!_stricmp(argv[1], "dse") || !_stricmp(argv[1], "setDSE"))
    {
        SetDSE(argc, argv);
    }
    else if (!_stricmp(argv[1], "wa") || !_stricmp(argv[1], "wait"))
    {
        Wait(argc, argv);
    }
    else
    {
        usage();
    }

    return 0;
}
