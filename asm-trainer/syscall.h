#pragma once

enum SyscallIndices
{
	SYSCALL_EXIT,                       // Stop emulation
	SYSCALL_PRINT,                      // Print string
	SYSCALL_MAP,                        // Map memory to address
	SYSCALL_UNMAP,                      // Unmap memory
	SYSCALL_MEM_MAPPED,                 // Check if memory is mapped in      
    SYSCALL_PRINT_CHAR,                 // This makes things a little easier by printing a single char

    //////////////////////////////////////////////////////////////////////////
    
    SYSCALL_EX_ADD_4 = 1000,            // Add 5 parameters fed into this function using standard argument format
};

extern void SyscallHandler(uc_engine* uc, void* userdata, uint32_t syscall, uint32_t& ret, uint32_t& arg1, uint32_t& arg2, uint32_t& arg3, uint32_t& arg4);
extern void SyscallHandler(uc_engine* uc, void* userdata, uint64_t syscall, uint64_t& ret, uint64_t& arg1, uint64_t& arg2, uint64_t& arg3, uint64_t& arg4);