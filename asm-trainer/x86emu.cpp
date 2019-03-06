#include "pch.h"
#include "unicorn/unicorn.h"
#include "emu.h"
#include "x86emu.h"

// 

enum Syscalls : int
{
    SYSCALL_EXIT,
    SYSCALL_PRINT,
    SYSCALL_MAP,
    SYSCALL_UNMAP,
    SYSCALL_MEM_MAPPED,
};

static void X86_SyscallHandler(
    uc_engine* uc,
    uint32_t syscall,
    uint32_t& ret,
    uint32_t& arg1,
    uint32_t& arg2,
    uint32_t& arg3)
{
    uc_err err = UC_ERR_OK;

    if (syscall == SYSCALL_EXIT)
    {
        uc_emu_stop(uc);
    }
    else if (syscall == SYSCALL_PRINT)
    {
        uint64_t addr = arg1;

        for (char c = -1; c != 0; ++addr)
        {
            uc_mem_read(uc, addr, &c, sizeof(char));
            putc(c, stdout);
        }

        putc('\n', stdout);
    }
    else if (syscall == SYSCALL_MAP)
    {
        err = uc_mem_map(uc, arg1, arg2, UC_PROT_ALL);

        ret = (err == UC_ERR_OK) ? 1 : 0;
    }
    else if (syscall == SYSCALL_UNMAP)
    {
        err = uc_mem_unmap(uc, arg1, arg2);

        ret = (err == UC_ERR_OK) ? 1 : 0;
    }
    else if (syscall == SYSCALL_MEM_MAPPED)
    {
        uint8_t i = 0;
        uc_err err = uc_mem_read(uc, arg1, &i, sizeof(uint8_t));
        ret = (err == UC_ERR_READ_UNMAPPED) ? 0 : 1;
    }
}

static void X86_InterruptHook(uc_engine* uc, void* user_data)
{
    uc_err err = UC_ERR_OK;

    uint32_t syscallIndex = 0;

    if (user_data == (void *)UC_X86_INS_SYSCALL)
    {
        err = uc_reg_read(uc, UC_X86_REG_EAX, &syscallIndex);
    }
    else if (user_data == (void *)UC_X86_INS_SYSENTER)
    {
        err = uc_reg_read(uc, UC_X86_REG_EAX, &syscallIndex);
    }
    else
    {
        // Unhandled, weird.
        return;
    }


    // Just grab a bunch of registers here so we don't have to make a bunch of calls
    // Being lazy =)
    uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0, r8 = 0, r9 = 0;

    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    uc_reg_read(uc, UC_X86_REG_EBX, &ebx);
    uc_reg_read(uc, UC_X86_REG_ECX, &ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &edx);

    X86_SyscallHandler(uc, syscallIndex, eax, ebx, ecx, edx);

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

    // Initialize the mapping
    const uint64_t codeMapSize = Emulator::PageAlignUp(size);

    err = uc_mem_map(m_uc, Emulator::StartAddress, codeMapSize, UC_PROT_ALL);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_mem_map failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    err = uc_mem_write(m_uc, Emulator::StartAddress, buffer, size);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_mem_write failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    // Setup fixed length stack
    const uint64_t stackAddress = Emulator::StartAddress + codeMapSize;
    const uint64_t stackSize = Emulator::PageAlignUp(m_stackSize);

    err = uc_mem_map(m_uc, stackAddress, stackSize, UC_PROT_ALL);

    if (err) 
    {
        std::cerr << "[ERROR] Emulator uc_mem_map failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    std::cout << ">>> Reserved " << std::hex << stackSize << std::dec << " bytes of stack space at address " << std::hex << stackAddress << std::dec << std::endl;

    err = uc_reg_write(m_uc, UC_X86_REG_ESP, &stackAddress);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_reg_write failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    uc_hook sysenter, syscall;
    err = uc_hook_add(m_uc, &syscall, UC_HOOK_INSN, X86_InterruptHook, (void *)(int)UC_X86_INS_SYSCALL, 1, 0, UC_X86_INS_SYSCALL);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_hook_add failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

    err = uc_hook_add(m_uc, &sysenter, UC_HOOK_INSN, X86_InterruptHook, (void *)(int)UC_X86_INS_SYSENTER, 1, 0, UC_X86_INS_SYSENTER);

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
    uc_err err = uc_emu_start(m_uc, Emulator::StartAddress, Emulator::StartAddress + m_bufferSize, 0, 0);

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
    uc_close(m_uc);

    m_uc = nullptr;
}