#include "pch.h"
#include "keystone/keystone.h"
#include "assembler.h"
#include "aarch32asm.h"
#include "emu.h"

bool ARM32Assembler::Initialize()
{
	ks_err err = ks_open(KS_ARCH_ARM, KS_MODE_ARM, &m_ks);

	if (err != KS_ERR_OK)
	{
		std::cerr << "[ERROR] Assembly engine returned error [" << ks_strerror(err) << "]" << std::endl;
		return false;
	}

	return true;
}

bool ARM32Assembler::Assemble(std::string& assembly, std::vector<uint8_t>& encoded)
{
	size_t size = 0, count = 0;

	unsigned char* enc = nullptr;

	int result = ks_asm(m_ks, assembly.c_str(), Emulator::StartAddress, &enc, &size, &count);

	if (result != 0)
	{
		std::cerr << "[ERROR] Assembly engine ks_asm returned error." << std::endl;
		return false;
	}

	if (size == 0)
	{
		std::cerr << "[ERROR] Generated assembly from ks_asm is 0 bytes." << std::endl;
		return false;
	}

	encoded.resize(size);

	memcpy(encoded.data(), enc, size);

	ks_free(enc);
	ks_close(m_ks);

	m_ks = nullptr;

	return true;
}