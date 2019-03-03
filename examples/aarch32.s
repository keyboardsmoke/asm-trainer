main:
ldr r0, .L2
bl print
b exit

exit:
svc #0 /* calls uc_emu_stop to cease emulation, that's why we won't return */

print:
mov r1, r0 /* r1 is the first argument for our syscall functions, r0 will store the result */
svc #1 /* print to console */
mov pc, lr /* simulated ret */

.LC0:
	.ascii "Hello, World!\000"

.L2:
	.word .LC0