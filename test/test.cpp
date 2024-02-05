// test.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include "../KernelCorridor/interface.h"
#include <cstdint>

HANDLE G_Driver = INVALID_HANDLE_VALUE;

bool SetThreadContext1(uint32_t tid, uint64_t usermode_handle, CONTEXT ctx)
{
    KCProtocols::REQUEST_SET_THREAD_CONTEXT request = {};
    request.tid = tid;
    request.usermode_handle = usermode_handle;
    request.ctx = ctx;
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_SET_THREAD_CONTEXT, &request, sizeof(request), 0, 0, &bytesReturned, 0))
    {
        return false;
    }
    return true;
}

bool GetThreadContext1(uint32_t tid, uint64_t usermode_handle, CONTEXT* ctx)
{
    KCProtocols::REQUEST_GET_THREAD_CONTEXT request = {};
    request.tid = tid;
    request.usermode_handle = usermode_handle;
    request.ctx = *ctx;
    KCProtocols::RESPONSE_GET_THREAD_CONTEXT response = {};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(G_Driver, CC_GET_THREAD_CONTEXT, &request, sizeof(request), &response, sizeof(response), &bytesReturned, 0))
    {
        return false;
    }
    *ctx = response.ctx;
    return true;
}

DWORD TestThread(void* param)
{
    while (true)
    {
        ;
    }
}

int main()
{
    G_Driver = CreateFileW(KC_SYMBOLIC_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (INVALID_HANDLE_VALUE == G_Driver)
    {
        return false;
    }

    DWORD threadid = 29460;
    auto handle = OpenThread(THREAD_ALL_ACCESS, 0, threadid);
    Sleep(1000);
    SuspendThread(handle);
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext1(threadid, 0, &ctx);
    ctx.Rax = 0x5555444433332222;
    //ctx.Rip = 0;
    //auto ret = SetThreadContext(handle, &ctx);

    //auto ret = SetThreadContext1(threadid, (uint64_t)0, ctx);


    ResumeThread(handle);

    while (true) {
        ;
    }

    return 0;

}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
