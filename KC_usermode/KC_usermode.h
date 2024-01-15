#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace KernelCorridor
{
	bool LoadDriver(const char* driver_file_path, const char* kernel_service_name);

	bool DeleteDriver(const char* kernel_service_name);

	bool Open();

	void Close();

	bool WriteProcessMemory(uint32_t pid, uint64_t address_to_write, const std::vector<uint8_t>& data);

	bool ReadProcessMemory(uint32_t pid, uint64_t address_to_read, uint32_t length_to_read, std::vector<uint8_t>& out);
}




