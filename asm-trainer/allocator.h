#pragma once

class Allocator
{
	struct Mapping
	{
		uint64_t address;
		uint64_t size;
		uint32_t permissions;

		bool IsWithinRange(uint64_t addr)
		{
			return (addr >= address && addr < (address + size));
		}
	};

public:
	Allocator() = delete;
	Allocator(uc_engine* uc, uint64_t pageSize) : m_uc(uc), m_pageSize(pageSize) {}

	bool Allocate(uint64_t size, uint64_t* address, uint32_t permissions = UC_PROT_ALL);
	bool Allocate(uint64_t address, uint64_t size, uint32_t permissions = UC_PROT_ALL);

	bool Map(void* buffer, uint64_t size, uint64_t* address, uint32_t permissions = UC_PROT_ALL);
	bool Map(void* buffer, uint64_t address, uint64_t size, uint32_t permissions = UC_PROT_ALL);

	bool Free(uint64_t address);

	bool IsMemoryUnmapped(uint64_t address);
	bool IsMemoryRegionFree(uint64_t address, uint64_t size);

    std::map<uint64_t, Mapping>& GetMappings() { return m_mappings; }

private:
	uint64_t FindNearestAvailableMemory(uint64_t size);

	uc_engine* m_uc;
	uint64_t m_pageSize;
	std::map<uint64_t, Mapping> m_mappings;
};