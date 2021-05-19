.CODE
CloseProtect64 PROC
	CLI ; ≤ª‘ –Ì÷–∂œ
	MOV rax, cr0
	AND rax, not 10000h
	MOV cr0, rax
	RET
CloseProtect64 ENDP

END