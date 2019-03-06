#include "pch.h"
#include "unicorn/unicorn.h"
#include "allocator.h"
#include "emu.h"
#include "aarch32emu.h"
#include "syscall.h"

struct SvcCall
{
	uint32_t svcNumber : 24;		// 
	uint32_t b1 : 4;				// 1 1 1 1
	uint32_t cond : 4;				//
};
static_assert(sizeof(SvcCall) == sizeof(uint32_t), "Invalid size for SvcCall");

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

	SyscallHandler(uc, call_value.svcNumber, r0, r1, r2, r3, r4);

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

	m_alloc = new Allocator(m_uc, 4096U);

	if (!m_alloc->Map(buffer, size, nullptr))
	{
		std::cerr << "[ERROR] Allocator failed to map code." << std::endl;

		return false;
	}

	std::cout << "Reserving stack space (" << m_stackSize << ")" << std::endl;

	uint64_t stackAddress = 0;
	if (!m_alloc->Allocate(m_stackSize, &stackAddress))
	{
		std::cerr << "[ERROR] Allocator failed to allocate stack space." << std::endl;

		return false;
	}

    std::cout << ">>> Reserved " << std::hex << m_stackSize << std::dec << " bytes of stack space at address " << std::hex << stackAddress << std::dec << std::endl;

    err = uc_reg_write(m_uc, UC_ARM_REG_SP, &stackAddress);

    if (err)
    {
        std::cerr << "[ERROR] Emulator uc_reg_write failed with error [" << uc_strerror(err) << "]" << std::endl;

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
	uc_err err = uc_emu_start(m_uc, 0, m_bufferSize, 0, 0);

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
	const int regIds[] =
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

	const char* regNames[] =
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