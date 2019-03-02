#pragma once

class Assembler
{
public:
	virtual bool Initialize() = 0;
	virtual bool Assemble(std::string& assembly, std::vector<uint8_t>& encoded) = 0;

protected:
	ks_engine* m_ks;
};