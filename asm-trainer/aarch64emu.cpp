#include "pch.h"
#include "unicorn/unicorn.h"
#include "allocator.h"
#include "emu.h"
#include "aarch64emu.h"
#include "syscall.h"

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

	uint64_t syscallNumber = call_value.svcNumber;

	// Just grab a bunch of registers here so we don't have to make a bunch of calls
	// Being lazy =)
	uint64_t x0 = 0, x1 = 0, x2 = 0, x3 = 0, x4 = 0;

	uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
	uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
	uc_reg_read(uc, UC_ARM64_REG_X2, &x2);
	uc_reg_read(uc, UC_ARM64_REG_X3, &x3);
	uc_reg_read(uc, UC_ARM64_REG_X4, &x4);

	SyscallHandler(uc, syscallNumber, x0, x1, x2, x3, x4);

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
	uc_err err = uc_emu_start(m_uc, 0, m_bufferSize, 0, 0);

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