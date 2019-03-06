#include "pch.h"
#include "unicorn/unicorn.h"
#include "allocator.h"

static uint64_t PageAlignUp(uint64_t pageSize, uint64_t address)
{
	return (((address) + pageSize - 1) & -pageSize);
}

bool Allocator::Allocate(uint64_t size, uint64_t* address, uint32_t permissions)
{
	size = PageAlignUp(m_pageSize, size);

	const uint64_t nearestAddress = FindNearestAvailableMemory(size);
	
	std::cout << "Nearest (" << nearestAddress << ")" << std::endl;

	if (address)
	{
		*address = nearestAddress;
	}

	return Allocate(nearestAddress, size, permissions);
}

bool Allocator::Allocate(uint64_t address, uint64_t size, uint32_t permissions)
{
	size = PageAlignUp(m_pageSize, size);

	if (IsMemoryRegionFree(address, size))
	{
		uc_err err = uc_mem_map(m_uc, address, size, permissions);

		if (err == UC_ERR_OK)
		{
			Mapping& map = m_mappings[address];
			map.address = address;
			map.size = size;
			map.permissions = permissions;

			return true;
		}
	}

	return false;
}

bool Allocator::Map(void* buffer, uint64_t size, uint64_t* address, uint32_t permissions)
{
	size = PageAlignUp(m_pageSize, size);

	const uint64_t nearestAddress = FindNearestAvailableMemory(size);

	if (Map(buffer, nearestAddress, size, permissions))
	{
		if (address)
		{
			*address = nearestAddress;
		}

		return true;
	}

	return false;
}

bool Allocator::Map(void* buffer, uint64_t address, uint64_t size, uint32_t permissions)
{
	size = PageAlignUp(m_pageSize, size);

	uc_err err = uc_mem_map_ptr(m_uc, address, size, permissions, buffer);

	if (err == UC_ERR_OK)
	{
		Mapping& map = m_mappings[address];
		map.address = address;
		map.size = size;
		map.permissions = permissions;

		return true;
	}

	return false;
}

bool Allocator::Free(uint64_t address)
{
	auto entry = m_mappings.find(address);
	if (entry == m_mappings.end())
	{
		return false;
	}

	Mapping& mapping = (*entry).second;

	uc_err err = uc_mem_unmap(m_uc, mapping.address, mapping.size);

	return (err == UC_ERR_OK);
}

bool Allocator::IsMemoryUnmapped(uint64_t address)
{
	uint8_t i = 0;
	uc_err err = uc_mem_read(m_uc, address, &i, sizeof(uint8_t));
	return (err == UC_ERR_READ_UNMAPPED);
}

bool Allocator::IsMemoryRegionFree(uint64_t address, uint64_t size)
{
	auto close_low = m_mappings.lower_bound(address);
	if (close_low == m_mappings.end())
	{
		// Nothing mapped yet
		return true;
	}

	Mapping& low_map = (*close_low).second;

	// You only have to check the lower bound of the range in this instance
	if (low_map.IsWithinRange(address))
	{
		return false;
	}

	auto close_high = close_low;

	// We need to check to see we don't bleed into the next entry
	if (++close_high != m_mappings.end())
	{
		Mapping& high_map = (*close_high).second;


		// You have to make sure address + size doesn't touch this either
		if (high_map.IsWithinRange(address) || 
			high_map.IsWithinRange(address + size))
		{
			return false;
		}
	}

	return true;
}

uint64_t Allocator::FindNearestAvailableMemory(uint64_t size)
{
	if (m_mappings.empty())
	{
		return 0;
	}

	for (auto i = m_mappings.begin(); i != m_mappings.end(); ++i)
	{
		Mapping& current = (*i).second;

		auto next = i;

		// We can check if there's space in between entries suitable for us
		if (++next != m_mappings.end())
		{
			Mapping& next_entry = (*next).second;

			uint64_t slack = next_entry.address - (current.address + current.size);

			if (slack >= size)
			{
				return (current.address + current.size);
			}
		}
		else
		{
			// Just give them the next available space
			return (current.address + current.size);
		}
	}

	__assume(0);
}
