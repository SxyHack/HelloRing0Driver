.CODE

CloseProtect64 PROC
	CLI ; 不允许中断
	MOV rax, cr0
	AND rax, not 10000h
	MOV cr0, rax
CloseProtect64 ENDP

ResetProtect64 PROC
	MOV rax, cr0
	OR  rax, 10000h
	MOV cr0, rax
	STI ; 允许中断
ResetProtect64 ENDP


END