main:
push HelloWorld
call print
call exit

exit:
mov eax, 0
syscall

print:
mov eax, 1
mov ebx, [esp+4]
syscall
ret

HelloWorld:
    .string "Hello, World!"