#pragma once

struct uc_struct;
typedef struct uc_struct uc_engine;

class Emulator
{
public:
	Emulator() : m_uc(nullptr) 
	{
	}

	virtual bool Initialize(void* buffer, size_t size) = 0;
	virtual bool Emulate() = 0;
	virtual void PrintContext(std::ostream& os) = 0;
	virtual void Close() = 0;

    uc_engine* GetEngine() { return m_uc; }

protected:
	Allocator* m_alloc;
	uc_engine* m_uc;
};