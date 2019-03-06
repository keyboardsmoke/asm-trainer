#include "pch.h"
#include "unicorn/unicorn.h"
#include "allocator.h"
#include "emu.h"
#include "x64emu.h"
#include "syscall.h"

static void X64_InterruptHook(uc_engine* uc, void* user_data)
{
    uc_err err = UC_ERR_OK;

    uint64_t syscallIndex = 0;

    if (user_data == (void *)UC_X86_INS_SYSCALL)
    {
        err = uc_reg_read(uc, UC_X86_REG_RAX, &syscallIndex);
    }
    else if (user_data == (void *)UC_X86_INS_SYSENTER)
    {
        err = uc_reg_read(uc, UC_X86_REG_RAX, &syscallIndex);
    }
    else 
    {
        // Unhandled, weird.
        return;
    }


    // Just grab a bunch of registers here so we don't have to make a bunch of calls
    // Being lazy =)
    uint64_t rax = 0, rbx = 0, rcx = 0, rdx = 0, r8 = 0, r9 = 0;

    uc_reg_read(uc, UC_X86_REG_RAX, &rax);
    uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_R8, &r8);
    uc_reg_read(uc, UC_X86_REG_R9, &r9);

    SyscallHandler(uc, syscallIndex, rax, rcx, rdx, r8, r9);

    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_write(uc, UC_X86_REG_R8, &r8);
    uc_reg_write(uc, UC_X86_REG_R9, &r9);
}

bool X64Emulator::Initialize(void* buffer, size_t size)
{
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &m_uc);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_open failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

	m_alloc = new Allocator(m_uc, 4096U);

	if (!m_alloc->Map(buffer, size, nullptr))
	{
		std::cerr << "[ERROR] Allocator failed to map code." << std::endl;

		return false;
	}

	uint64_t stackAddress = 0;
	if (!m_alloc->Allocate(m_stackSize, &stackAddress))
	{
		std::cerr << "[ERROR] Allocator failed to allocate stack space." << std::endl;

		return false;
	}

    std::cout << ">>> Reserved " << std::hex << m_stackSize << std::dec << " bytes of stack space at address " << std::hex << stackAddress << std::dec << std::endl;

    err = uc_reg_write(m_uc, UC_X86_REG_RSP, &stackAddress);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_reg_write failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    uc_hook sysenter, syscall;
    err = uc_hook_add(m_uc, &syscall, UC_HOOK_INSN, X64_InterruptHook, (void *)(int)UC_X86_INS_SYSCALL, 1, 0, UC_X86_INS_SYSCALL);
    
    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_hook_add failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    err = uc_hook_add(m_uc, &sysenter, UC_HOOK_INSN, X64_InterruptHook, (void *)(int)UC_X86_INS_SYSENTER, 1, 0, UC_X86_INS_SYSENTER);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_hook_add failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    m_bufferSize = size;

    return true;
}

bool X64Emulator::Emulate()
{
    uc_err err = uc_emu_start(m_uc, 0, m_bufferSize, 0, 0);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_emu_start failed with error [" << uc_strerror(err) << "]" << std::endl;

        PrintContext(std::cerr);

        return false;
    }

    return true;
}

template<size_t N>
uc_err ReadRegisterBatch(uc_engine* uc, const int(&registerIds)[N], uint64_t(&values)[N])
{
    void* ptrs[N] = { nullptr };

    for (size_t i = 0; i < N; ++i)
    {
        ptrs[i] = &values[i];
    }

    return uc_reg_read_batch(uc, const_cast<int *>(registerIds), ptrs, N);
}

void X64Emulator::PrintContext(std::ostream& os)
{
    const int regIds[] =
    {
        UC_X86_REG_RAX,
        UC_X86_REG_RBX,
        UC_X86_REG_RCX,
        UC_X86_REG_RDX,
        UC_X86_REG_R8,
        UC_X86_REG_R9,
        UC_X86_REG_RIP,
        UC_X86_REG_RSP
    };

    const char* regNames[] =
    {
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "R8",
        "R9",
        "RIP",
        "RSP"
    };

    os << "Context: {" << std::endl;

    constexpr size_t count = sizeof(regIds) / sizeof(int);

    uint64_t values[count] = { 0 };

    uc_err err = ReadRegisterBatch(m_uc, regIds, values);
    if (err)
    {
        os << "\t<ERROR>" << std::endl;
    }
    else
    {
        for (size_t i = 0; i < count; i++)
        {
            os << "\t" << regNames[i] << " = " << values[i] << std::endl;
        }
    }

    os << "}" << std::endl;
}

void X64Emulator::Close()
{
    uc_close(m_uc);

    m_uc = nullptr;
}