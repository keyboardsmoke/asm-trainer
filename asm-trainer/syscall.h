#pragma once

enum SyscallIndices
{
	SYSCALL_EXIT,
	SYSCALL_PRINT,
	SYSCALL_MAP,
	SYSCALL_UNMAP,
	SYSCALL_MEM_MAPPED,
};

extern void SyscallHandler(uc_engine* uc, void* userdata, uint32_t syscall, uint32_t& ret, uint32_t& arg1, uint32_t& arg2, uint32_t& arg3, uint32_t& arg4);
extern void SyscallHandler(uc_engine* uc, void* userdata, uint64_t syscall, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4);