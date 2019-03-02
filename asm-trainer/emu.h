#pragma once

struct uc_struct;
typedef struct uc_struct uc_engine;

class Emulator
{
public:
	static const uint64_t StartAddress = 0U;
	static const uint64_t PageSize = 4096U;

	Emulator() : m_uc(nullptr) {}

	virtual bool Initialize(void* buffer, size_t size) = 0;
	virtual bool Emulate() = 0;
	virtual void PrintContext(std::ostream& os) = 0;
	virtual void Close() = 0;

	static uint64_t PageAlignUp(uint64_t address)
	{
		return (((address)+PageSize - 1) & -PageSize);
	}

protected:
	uc_engine* m_uc;
};