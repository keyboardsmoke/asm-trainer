#pragma once

class X86Emulator : public Emulator
{
public:
    X86Emulator(uint64_t stackSize) : Emulator(), m_bufferSize(0), m_stackSize(stackSize) {}

    virtual bool Initialize(void* buffer, size_t size) override;
    virtual bool Emulate() override;
    virtual void PrintContext(std::ostream& os) override;
    virtual void Close() override;

private:
    uint64_t m_bufferSize;
    uint64_t m_stackSize;
};