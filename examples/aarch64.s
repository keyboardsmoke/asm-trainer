main:
adrp x1, .LC0
add x1, x1, #:lo12:.LC0
bl print
b exit

exit:
svc #0

print:
svc #1
ret

.LC0:
	.string "I did it!"