#include "pch.h"
#include "unicorn/unicorn.h"
#include "syscall.h"
#include "util.h"

typedef void(*SyscallHandler_t)(uc_engine* uc, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4);

struct RegisteredSyscall
{
	uint64_t syscallIndex;
	SyscallHandler_t handler;
};

void exit(uc_engine* uc, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	uc_emu_stop(uc);
}

void print(uc_engine* uc, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	ret = 0;

	std::string str;
	if (emuutil::ReadStringFromMemory(uc, arg1, str))
	{
		std::cout << str << std::endl;

		ret = 1;
	}
}

void map_memory(uc_engine* uc, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	uc_err err = uc_mem_map(uc, arg1, arg2, UC_PROT_ALL);

	ret = (err == UC_ERR_OK) ? 1 : 0;
}

void unmap_memory(uc_engine* uc, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	uc_err err = uc_mem_unmap(uc, arg1, arg2);

	ret = (err == UC_ERR_OK) ? 1 : 0;
}

void is_mem_mapped(uc_engine* uc, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	uint8_t i = 0;
	uc_err err = uc_mem_read(uc, arg1, &i, sizeof(uint8_t));
	ret = (err == UC_ERR_READ_UNMAPPED) ? 0 : 1;
}

RegisteredSyscall registered_handlers[] =
{
{ SYSCALL_EXIT, exit },
{ SYSCALL_PRINT, print },
{ SYSCALL_MAP, map_memory },
{ SYSCALL_UNMAP, unmap_memory },
{ SYSCALL_MEM_MAPPED, is_mem_mapped }
};

void SyscallHandler(uc_engine* uc, uint32_t syscall, uint32_t& ret, uint32_t& arg1, uint32_t& arg2, uint32_t& arg3, uint32_t& arg4)
{
	uint64_t syscall_ext = syscall;
	uint64_t ret_ext = ret;
	uint64_t arg1_ext = arg1;
	uint64_t arg2_ext = arg2;
	uint64_t arg3_ext = arg3;
	uint64_t arg4_ext = arg4;

	SyscallHandler(uc, syscall_ext, ret_ext, arg1_ext, arg2_ext, arg3_ext, arg4_ext);

	ret = ret_ext;
	arg1 = arg1_ext;
	arg2 = arg2_ext;
	arg3 = arg3_ext;
	arg4 = arg4_ext;
}

void SyscallHandler(uc_engine* uc, uint64_t syscall, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	if (syscall < _countof(registered_handlers))
	{
		registered_handlers[syscall].handler(uc, ret, arg1, arg2, arg3, arg4);
	}
}