#pragma once

class X64Emulator : public Emulator
{
public:
    X64Emulator(uint64_t stackSize = Emulator::PageSize) : Emulator(), m_bufferSize(0), m_stackSize(stackSize) {}

    virtual bool Initialize(void* buffer, size_t size) override;
    virtual bool Emulate() override;
    virtual void PrintContext(std::ostream& os) override;
    virtual void Close() override;

private:
    uint64_t m_bufferSize;
    uint64_t m_stackSize;
};