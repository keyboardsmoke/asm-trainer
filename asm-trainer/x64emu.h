#pragma once

class X64Emulator : public Emulator
{
public:
    X64Emulator(uint64_t stackSize) : Emulator(), m_bufferSize(0), m_stackSize(stackSize) {}

    bool Initialize(void* buffer, size_t size) override;
    bool Emulate() override;
    void PrintContext(std::ostream& os) override;
    void Close() override;

private:
    uint64_t m_bufferSize;
    uint64_t m_stackSize;
};