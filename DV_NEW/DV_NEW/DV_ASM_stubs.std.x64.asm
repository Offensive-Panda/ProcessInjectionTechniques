.data
currentHash DWORD 0

.code
EXTERN SW2_GetSyscallNumber: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    DB 62h                     
	DB 0h                     
	DB 0h                     
	DB 67h                     
	DB 62h                     
	DB 0h                     
	DB 0h                     
	DB 67h                
    ret
WhisperMain ENDP

NTOP0 PROC
    mov currentHash, 0E123CABCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NTOP0 ENDP

NAVM1 PROC
    mov currentHash, 003970B07h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NAVM1 ENDP

NWVM2 PROC
    mov currentHash, 09D9570F6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NWVM2 ENDP

end