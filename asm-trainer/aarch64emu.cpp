#include "pch.h"
#include "unicorn/unicorn.h"
#include "emu.h"
#include "aarch64emu.h"

struct SvcCall
{
	uint32_t b1 : 1;				// 1
	uint32_t b2 : 1;				// 0
	uint32_t b3 : 3;				// 0 0 0
	uint32_t svcNumber : 16;		//
	uint32_t b4 : 3;				// 0 0 0
	uint32_t b5 : 8;				// 0 0 1 0 1 0 1 1
};
static_assert(sizeof(SvcCall) == sizeof(uint32_t), "Invalid size for SvcCall");

enum Syscalls : int
{
	SYSCALL_EXIT,
	SYSCALL_PRINT,
	SYSCALL_MAP,
	SYSCALL_UNMAP,
	SYSCALL_MEM_MAPPED,
};

static void ARM64_SyscallHandler(
	uc_engine* uc, 
	uint64_t syscall, 
	uint64_t& ret, 
	uint64_t& arg1, 
	uint64_t& arg2, 
	uint64_t& arg3, 
	uint64_t& arg4)
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

static void ARM64_InterruptHook(uc_engine* uc, uint32_t number, void* user_data)
{
	uint64_t pc;
	uc_err err = uc_reg_read(uc, UC_ARM64_REG_PC, &pc);

	if (err != UC_ERR_OK)
	{
		// Don't handle this
		return;
	}

	SvcCall call_value = { 0 };
	err = uc_mem_read(uc, pc - sizeof(SvcCall), &call_value, sizeof(call_value));

	if (err != UC_ERR_OK)
	{
		return;
	}

	// We are NOT handling a (valid) SVC interrupt
	if (number != 2 ||
		call_value.b1 != 1 ||
		call_value.b2 != 0 ||
		call_value.b3 != 0 ||
		call_value.b4 != 0 ||
		call_value.b5 != 212)
	{
		return;
	}

	// Just grab a bunch of registers here so we don't have to make a bunch of calls
	// Being lazy =)
	uint64_t x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0;

	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_read(uc, UC_ARM64_REG_X3, &x3);
	uc_reg_read(uc, UC_ARM64_REG_X4, &x4);

	ARM64_SyscallHandler(uc, call_value.svcNumber, x0, x1, x2, x3, x4);

	uc_reg_write(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_write(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_write(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_write(uc, UC_ARM64_REG_X3, &x3);
	uc_reg_write(uc, UC_ARM64_REG_X4, &x4);
}

bool ARM64Emulator::Initialize(void* buffer, size_t size)
{
	uc_err err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &m_uc);

	if (err)
	{
		std::cerr << "[ERROR] Emulator uc_open failed with error [" << uc_strerror(err) << "]" << std::endl;

		return false;
	}

	// Initialize the mapping
    const uint64_t codeMapSize = Emulator::PageAlignUp(size);

	err = uc_mem_map(m_uc, Emulator::StartAddress, Emulator::PageAlignUp(size), UC_PROT_ALL);
	
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

    err = uc_reg_write(m_uc, UC_ARM64_REG_SP, &stackAddress);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_reg_write failed with error [" << uc_strerror(err) << "]" << std::endl;

        return false;
    }

	uc_hook trace;
	err = uc_hook_add(m_uc, &trace, UC_HOOK_INTR, ARM64_InterruptHook, nullptr, 0, -1);

	if (err)
	{
		std::cerr << "[ERROR] Emulator uc_hook_add failed with error [" << uc_strerror(err) << "]" << std::endl;

		return false;
	}

	m_bufferSize = size;

	return true;
}

bool ARM64Emulator::Emulate()
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
uc_err ReadRegisterBatch(uc_engine* uc, const int (&registerIds)[N], uint64_t (&values)[N])
{
	void* ptrs[N] = { nullptr };

	for (size_t i = 0; i < N; ++i)
	{
		ptrs[i] = &values[i];
	}

	return uc_reg_read_batch(uc, const_cast<int *>(registerIds), ptrs, N);
}

void ARM64Emulator::PrintContext(std::ostream& os)
{
	const int regIds[] =
	{
		UC_ARM64_REG_X0,
		UC_ARM64_REG_X1,
		UC_ARM64_REG_X2,
		UC_ARM64_REG_X3,
		UC_ARM64_REG_X4,
		UC_ARM64_REG_X5,
		UC_ARM64_REG_PC,
		UC_ARM64_REG_FP,
		UC_ARM64_REG_LR
	};

	const char* regNames[] = 
	{
		"X0",
		"X1",
		"X2",
		"X3",
		"X4", 
		"X5",
		"PC",
		"FP",
		"LR"
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

void ARM64Emulator::Close()
{
	uc_close(m_uc);

	m_uc = nullptr;
}