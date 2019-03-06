main:
call test_mapped
call map_memory
call test_mapped
call try_set_mem
call exit

try_set_mem:
mov rax, qword ptr [mem_address]
mov qword ptr [rax], 4
cmp qword ptr [rax], 4
jz mem_ok
mov rcx, write_memory_test_failed
call print
jmp end_of_try_set_mem
mem_ok:
mov rcx, write_memory_test_ok
call print
end_of_try_set_mem:
ret

test_mapped:
mov rcx, [mem_address]
call is_mem_mapped
cmp rax, 0
jz main_not_mapped
mov rcx, mem_mapped
call print
jmp end_of_test_mapped
main_not_mapped:
mov rcx, mem_not_mapped
call print
end_of_test_mapped:
ret

map_memory:
mov rcx, attempting_map
call print
mov rax, 2
mov rcx, [mem_address]
mov rdx, 0x1000
syscall
ret

is_mem_mapped:
mov rax, 4
syscall
ret

exit:
mov rax, 0
syscall

print:
mov rax, 1
syscall
ret

mem_address:
	.quad 0x4000
mem_not_mapped:
	.string "The memory at 0x4000 is not mapped"
mem_mapped:
    .string "The memory at 0x4000 is mapped"
attempting_map:
	.string "Attempting to map memory at 0x4000"
write_memory_test_failed:
	.string "Attempted to write value to 0x4000 and failed."
write_memory_test_ok:
	.string "Wrote a value to 0x4000 successfully!"