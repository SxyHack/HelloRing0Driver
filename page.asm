.CODE

CloseProtect64 PROC
	CLI ; �������ж�
	MOV rax, cr0
	AND rax, not 10000h
	MOV cr0, rax
CloseProtect64 ENDP

ResetProtect64 PROC
	MOV rax, cr0
	OR  rax, 10000h
	MOV cr0, rax
	STI ; �����ж�
ResetProtect64 ENDP


END