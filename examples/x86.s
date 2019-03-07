main:
push HelloWorld
call print
add esp, 4
call exit

exit:
mov eax, 0
syscall

print:
mov eax, 1
syscall /* syscall takes esp+4 as the first argument, but the push already shifted the stack before this call, so we don't have to access it */
ret

HelloWorld:
    .string "Hello, World!"