#include "pch.h"
#include "keystone/keystone.h"
#include "assembler.h"
#include "x86asm.h"

bool X86Assembler::Initialize()
{
    ks_err err = ks_open(KS_ARCH_X86, KS_MODE_32, &m_ks);

    if (err != KS_ERR_OK)
    {
        std::cerr << "[ERROR] Assembly engine returned error [" << ks_strerror(err) << "]" << std::endl;
        return false;
    }

    return true;
}

bool X86Assembler::Assemble(std::string& assembly, std::vector<uint8_t>& encoded)
{
    size_t size = 0, count = 0;

    unsigned char* enc = nullptr;

    int result = ks_asm(m_ks, assembly.c_str(), 0, &enc, &size, &count);

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