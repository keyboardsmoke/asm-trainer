#include "pch.h"
#include "unicorn/unicorn.h"
#include "allocator.h"
#include "emu.h"
#include "x86emu.h"
#include "syscall.h"

static void X86_SyscallHook(uc_engine* uc, void* user_data)
{
    uc_err err = UC_ERR_OK;

    uint32_t syscallIndex = 0;

    err = uc_reg_read(uc, UC_X86_REG_EAX, &syscallIndex);

    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0, stub = 0;

    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);

    SyscallHandler(uc, user_data, syscallIndex, eax, ebx, ecx, edx, stub);

    uc_reg_write(uc, UC_X86_REG_EAX, &eax);
    uc_reg_write(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_write(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &edx);
}

bool X86Emulator::Initialize(void* buffer, size_t size)
{
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_32, &m_uc);

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

    err = uc_reg_write(m_uc, UC_X86_REG_ESP, &stackAddress);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_reg_write failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    uc_hook syscall;
    err = uc_hook_add(m_uc, &syscall, UC_HOOK_INSN, X86_SyscallHook, (void *)(int)UC_X86_INS_SYSCALL, 1, 0, UC_X86_INS_SYSCALL);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_hook_add failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    m_bufferSize = size;

    return true;
}

bool X86Emulator::Emulate()
{
    uc_err err = uc_emu_start(m_uc, 0, m_bufferSize, 0, 0);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_emu_start failed with error [" << uc_strerror(err) << "]" << std::endl;
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

void X86Emulator::PrintContext(std::ostream& os)
{
    const int regIds[] =
    {
        UC_X86_REG_EAX,
        UC_X86_REG_EBX,
        UC_X86_REG_ECX,
        UC_X86_REG_EDX,
        UC_X86_REG_EIP,
        UC_X86_REG_ESP
    };

    const char* regNames[] =
    {
        "EAX",
        "EBX",
        "ECX",
        "EDX",
        "EIP",
        "ESP"
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

void X86Emulator::Close()
{
    if (m_uc != nullptr)
        uc_close(m_uc);

    m_uc = nullptr;
}