#pragma once

class ARM64Emulator : public Emulator
{
public:
	ARM64Emulator() : Emulator(), m_bufferSize(0) {}

	virtual bool Initialize(void* buffer, size_t size) override;
	virtual bool Emulate() override;
	virtual void PrintContext(std::ostream& os) override;
	virtual void Close() override;

private:
	uint64_t m_bufferSize;
};