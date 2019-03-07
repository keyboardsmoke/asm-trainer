#include "pch.h"
#include "unicorn/unicorn.h"
#include "syscall.h"
#include "util.h"
#include "allocator.h"
#include "emu.h"
#include "aarch32emu.h"
#include "aarch64emu.h"
#include "x86emu.h"
#include "x64emu.h"

typedef void(*SyscallHandler_t)(uc_engine* uc, void* userdata, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4);

struct RegisteredSyscall
{
	uint64_t syscallIndex;
	SyscallHandler_t handler;
};

void exit(uc_engine* uc, void* userdata, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	uc_emu_stop(uc);
}

void print(uc_engine* uc, void* userdata, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	ret = 0;

	std::string str;
	if (emuutil::ReadStringFromMemory(uc, arg1, str))
	{
		std::cout << str << std::endl;

		ret = 1;
	}
}

void map_memory(uc_engine* uc, void* userdata, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
    // 

	const uc_err err = uc_mem_map(uc, arg1, arg2, UC_PROT_ALL);

	ret = (err == UC_ERR_OK) ? 1 : 0;
}

void unmap_memory(uc_engine* uc, void* userdata, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	const uc_err err = uc_mem_unmap(uc, arg1, arg2);

	ret = (err == UC_ERR_OK) ? 1 : 0;
}

void is_mem_mapped(uc_engine* uc, void* userdata, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	uint8_t i = 0;
	const uc_err err = uc_mem_read(uc, arg1, &i, sizeof(uint8_t));
	ret = (err == UC_ERR_READ_UNMAPPED) ? 0 : 1;
}

//////////////////////////////////////////////////////////////////////////
// Reserved syscalls for learning purposes
//////////////////////////////////////////////////////////////////////////

void ex_add_4(uc_engine* uc, void* userdata, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
    Emulator* emu = reinterpret_cast<Emulator *>(userdata);

    if (emu->is<ARM32Emulator>())
    {
        // r0, r1, r2, r3
        
    }
    else if (emu->is<ARM64Emulator>()) 
    {
        // x0, x1, x2, x3
    }
    else if (emu->is<X86Emulator>()) 
    {
        // esp + 4, esp + 8, esp + 0xc, esp + 0x10
    }
    else if (emu->is<X64Emulator>()) 
    {
        // rcx, rdx, r8, r9
    }
}

RegisteredSyscall registered_handlers[] =
{
{ SYSCALL_EXIT, exit },
{ SYSCALL_PRINT, print },
{ SYSCALL_MAP, map_memory },
{ SYSCALL_UNMAP, unmap_memory },
{ SYSCALL_MEM_MAPPED, is_mem_mapped },

{ SYSCALL_EX_ADD_4, ex_add_4 },
};

void SyscallHandler(uc_engine* uc, void* userdata, uint32_t syscall, uint32_t& ret, uint32_t& arg1, uint32_t& arg2, uint32_t& arg3, uint32_t& arg4)
{
	const uint64_t syscallExt = syscall;

	uint64_t retExt = ret;
	uint64_t arg1Ext = arg1;
	uint64_t arg2Ext = arg2;
	uint64_t arg3Ext = arg3;
	uint64_t arg4Ext = arg4;

	SyscallHandler(uc, userdata, syscallExt, retExt, arg1Ext, arg2Ext, arg3Ext, arg4Ext);

	ret = static_cast<uint32_t>(retExt);
    arg1 = static_cast<uint32_t>(arg1Ext);
    arg2 = static_cast<uint32_t>(arg2Ext);
    arg3 = static_cast<uint32_t>(arg3Ext);
    arg4 = static_cast<uint32_t>(arg4Ext);
}

void SyscallHandler(uc_engine* uc, void* userdata, uint64_t syscall, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4)
{
	if (syscall < _countof(registered_handlers))
	{
		registered_handlers[syscall].handler(uc, userdata, ret, arg1, arg2, arg3, arg4);
	}
}