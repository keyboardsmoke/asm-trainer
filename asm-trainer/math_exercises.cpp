#include "pch.h"
#include "unicorn/unicorn.h"
#include "allocator.h"
#include "emu.h"
#include "aarch32emu.h"
#include "aarch64emu.h"
#include "x64emu.h"
#include "x86emu.h"
#include "exercise.h"
#include "math_exercises.h"

// Simple test, take parameters passed to your function and 
// 0x12 ^ 0x75 == 0x67

bool SimpleXorExercise::InitializeEngineState()
{
    uint64_t arg1 = 0x12;
    uint64_t arg2 = 0x75;

    if (ARM64Emulator* aarch64 = dynamic_cast<ARM64Emulator *>(m_emu))
    {
        if (uc_reg_write(m_emu->GetEngine(), UC_ARM64_REG_X0, &arg1) != UC_ERR_OK ||
            uc_reg_write(m_emu->GetEngine(), UC_ARM64_REG_X1, &arg2) != UC_ERR_OK) 
        {
            return false;
        }
    }
    else if (ARM32Emulator* aarch32 = dynamic_cast<ARM32Emulator *>(m_emu))
    {
        if (uc_reg_write(m_emu->GetEngine(), UC_ARM_REG_R0, &arg1) != UC_ERR_OK ||
            uc_reg_write(m_emu->GetEngine(), UC_ARM_REG_R1, &arg2) != UC_ERR_OK)
        {
            return false;
        }
    }
    else if (X64Emulator* x64 = dynamic_cast<X64Emulator *>(m_emu))
    {
        if (uc_reg_write(m_emu->GetEngine(), UC_X86_REG_RCX, &arg1) != UC_ERR_OK ||
            uc_reg_write(m_emu->GetEngine(), UC_X86_REG_RDX, &arg2) != UC_ERR_OK)
        {
            return false;
        }
    }
    else if (X86Emulator* x86 = dynamic_cast<X86Emulator *>(m_emu))
    {
        uint64_t esp = 0;

        if (uc_reg_read(m_emu->GetEngine(), UC_X86_REG_ESP, &esp) != UC_ERR_OK) 
        {
            return false;
        }

        if (uc_mem_write(m_emu->GetEngine(), esp + 4, &arg1, sizeof(uint32_t)) != UC_ERR_OK ||
            uc_mem_write(m_emu->GetEngine(), esp + 8, &arg2, sizeof(uint32_t)) != UC_ERR_OK) 
        {
            return false;
        }
        
    }

    return true;
}

bool SimpleXorExercise::Evaluate()
{
    uint64_t result = 0;

    uc_err err = UC_ERR_OK;

    if (ARM64Emulator* aarch64 = dynamic_cast<ARM64Emulator *>(m_emu)) 
    {
        err = uc_reg_read(m_emu->GetEngine(), UC_ARM64_REG_X0, &result);
    }
    else if (ARM32Emulator* aarch32 = dynamic_cast<ARM32Emulator *>(m_emu)) 
    {
        err = uc_reg_read(m_emu->GetEngine(), UC_ARM_REG_R0, &result);
    }
    else if (X64Emulator* x64 = dynamic_cast<X64Emulator *>(m_emu))
    {
        err = uc_reg_read(m_emu->GetEngine(), UC_X86_REG_RAX, &result);
    }
    else if (X86Emulator* x86 = dynamic_cast<X86Emulator *>(m_emu)) 
    {
        err = uc_reg_read(m_emu->GetEngine(), UC_X86_REG_EAX, &result);
    }

    if (err != UC_ERR_OK)
    {
        return false;
    }

    if (result != 0x67)
    {
        return false;
    }

    return true;
}