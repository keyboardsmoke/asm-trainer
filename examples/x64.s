main:
mov rcx, HelloWorld
call print
call exit

exit:
mov rax, 0
syscall

print:
mov rax, 1
syscall
ret

HelloWorld:
    .string "Hello, World!"