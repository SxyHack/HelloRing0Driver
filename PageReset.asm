.CODE
ResetProtect64 PROC
	MOV rax, cr0
	OR  rax, 10000h
	MOV cr0, rax
	STI ; �����ж�
	RET
ResetProtect64 ENDP
END