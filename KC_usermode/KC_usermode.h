#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <windows.h>

namespace KernelCorridor
{
	bool CreateDriverServiceAndLoadDriver(const std::wstring& driver_file_path, const std::wstring& service_name, bool append_random_suffix, std::wstring& actual_service_name);

	bool StopDriverServiceAndDeleteIt(const std::wstring& kernel_service_name);

	bool Open();

	void Close();

	bool WriteProcessMemory(uint32_t pid, uint64_t address_to_write, const std::vector<uint8_t>& data, uint32_t& bytes_written, uint32_t method_id = 1);

	bool ReadProcessMemory(uint32_t pid, uint64_t address_to_read, uint32_t length_to_read, std::vector<uint8_t>& out, uint32_t method_id = 0);

	bool SetThreadContext(uint32_t tid, CONTEXT* ctx);

	bool GetThreadContext(uint32_t tid, CONTEXT* ctx);

	bool AllocProcessMemory(uint32_t pid, uint64_t* base, uint32_t* size, uint32_t protect);

	bool FreeAllocedProcessMemory(uint32_t pid, uint64_t base);

	HANDLE OpenProcess(uint32_t pid, uint32_t access, bool request_kernel_mode_handle);
}




