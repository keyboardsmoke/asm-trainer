#include "pch.h"
#include "unicorn/unicorn.h"
#include "emu.h"
#include "aarch32emu.h"

struct SvcCall
{
	uint32_t svcNumber : 24;		// 
	uint32_t b1 : 4;				// 1 1 1 1
	uint32_t cond : 4;				//
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

static void ARM32_SyscallHandler(
	uc_engine* uc,
	uint32_t syscall,
	uint32_t& ret,
	uint32_t& arg1,
	uint32_t& arg2,
	uint32_t& arg3,
	uint32_t& arg4)
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

static void ARM32_InterruptHook(uc_engine* uc, uint32_t number, void* user_data)
{
	uint32_t pc;
	uc_err err = uc_reg_read(uc, UC_ARM_REG_PC, &pc);

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
	if (number != 2 || call_value.b1 != 15)
	{
		return;
	}

	// Just grab a bunch of registers here so we don't have to make a bunch of calls
	// Being lazy =)
	uint32_t r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0;

	uc_reg_read(uc, UC_ARM_REG_R0, &r0);
	uc_reg_read(uc, UC_ARM_REG_R1, &r1);
	uc_reg_read(uc, UC_ARM_REG_R2, &r2);
	uc_reg_read(uc, UC_ARM_REG_R3, &r3);
	uc_reg_read(uc, UC_ARM_REG_R4, &r4);

	ARM32_SyscallHandler(uc, call_value.svcNumber, r0, r1, r2, r3, r4);

	uc_reg_write(uc, UC_ARM_REG_R0, &r0);
	uc_reg_write(uc, UC_ARM_REG_R1, &r1);
	uc_reg_write(uc, UC_ARM_REG_R2, &r2);
	uc_reg_write(uc, UC_ARM_REG_R3, &r3);
	uc_reg_write(uc, UC_ARM_REG_R4, &r4);
}

bool ARM32Emulator::Initialize(void* buffer, size_t size)
{
	uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &m_uc);

	if (err)
	{
		std::cerr << "[ERROR] Emulator uc_open failed with error [" << uc_strerror(err) << "]" << std::endl;

		return false;
	}

	// Initialize the mapping
	size_t map_size = Emulator::PageAlignUp(size);

	err = uc_mem_map(m_uc, Emulator::StartAddress, map_size, UC_PROT_ALL);

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

	uc_hook trace;
	err = uc_hook_add(m_uc, &trace, UC_HOOK_INTR, ARM32_InterruptHook, nullptr, 0, -1);

	if (err)
	{
		std::cerr << "[ERROR] Emulator uc_hook_add failed with error [" << uc_strerror(err) << "]" << std::endl;

		return false;
	}

	m_bufferSize = size;

	return true;
}

bool ARM32Emulator::Emulate()
{
	uc_err err = uc_emu_start(m_uc, Emulator::StartAddress, Emulator::StartAddress + m_bufferSize, 0, 0);

	//

	if (err)
	{
		std::cerr << "[ERROR] Emulator uc_emu_start failed with error [" << uc_strerror(err) << "]" << std::endl;
		return false;
	}

	return true;
}

template<size_t N>
uc_err ReadRegisterBatch(uc_engine* uc, const int(&registerIds)[N], uint32_t(&values)[N])
{
	void* ptrs[N] = { nullptr };

	for (size_t i = 0; i < N; ++i)
	{
		ptrs[i] = &values[i];
	}

	return uc_reg_read_batch(uc, const_cast<int *>(registerIds), ptrs, N);
}

void ARM32Emulator::PrintContext(std::ostream& os)
{
	const int regIds[9] =
	{
		UC_ARM_REG_R0,
		UC_ARM_REG_R1,
		UC_ARM_REG_R2,
		UC_ARM_REG_R3,
		UC_ARM_REG_R4,
		UC_ARM_REG_R5,
		UC_ARM_REG_PC,
		UC_ARM_REG_FP,
		UC_ARM_REG_LR
	};

	const char* regNames[9] =
	{
		"R0",
		"R1",
		"R2",
		"R3",
		"R4",
		"R5",
		"PC",
		"FP",
		"LR"
	};

	os << "Context: {" << std::endl;

	constexpr size_t count = sizeof(regIds) / sizeof(int);

	uint32_t values[count] = { 0 };

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

void ARM32Emulator::Close()
{
	uc_close(m_uc);

	m_uc = nullptr;
}