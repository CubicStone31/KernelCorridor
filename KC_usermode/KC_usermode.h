#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace KernelCorridor
{
	bool CreateDriverServiceAndLoadDriver(const std::wstring& driver_file_path, const std::wstring& service_name, bool append_random_suffix, std::wstring& actual_service_name);

	bool StopDriverServiceAndDeleteIt(const std::wstring& kernel_service_name);

	bool Open();

	void Close();

	bool WriteProcessMemory(uint32_t pid, uint64_t address_to_write, const std::vector<uint8_t>& data);

	bool ReadProcessMemory(uint32_t pid, uint64_t address_to_read, uint32_t length_to_read, std::vector<uint8_t>& out);
}




