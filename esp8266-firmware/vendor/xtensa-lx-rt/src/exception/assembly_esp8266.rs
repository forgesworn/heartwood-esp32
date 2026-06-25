use core::arch::naked_asm;

// Frame-offset constants + the SAVE_CONTEXT / RESTORE_CONTEXT macros.
//
// Originally these lived in shared `global_asm!` blocks and the exception
// vectors were `asm!(..., options(noreturn))` naked bodies. The modern compiler
// requires `naked_asm!`, and (the subtle part) the integrated assembler does
// NOT guarantee that `global_asm!` blocks are emitted before the naked bodies
// that use these macros — the original split produced "macro SAVE_CONTEXT
// undefined" at the use sites. All the asm DOES land in one assembly unit,
// though, so we prepend the definitions to every body behind an `.ifndef`
// guard: whichever body is assembled first defines them (once), the rest skip,
// and the shared scope makes them visible everywhere — order-independent.
macro_rules! naked_ctx_asm {
    ($body:literal $(,)?) => {
        naked_asm!(concat!(
            r#"
            .ifndef HW_CTX_DEFS
            .set HW_CTX_DEFS, 1

            .set XT_STK_PC,        0
            .set XT_STK_PS,        4
            .set XT_STK_A0,        8
            .set XT_STK_A1,       12
            .set XT_STK_A2,       16
            .set XT_STK_A3,       20
            .set XT_STK_A4,       24
            .set XT_STK_A5,       28
            .set XT_STK_A6,       32
            .set XT_STK_A7,       36
            .set XT_STK_A8,       40
            .set XT_STK_A9,       44
            .set XT_STK_A10,      48
            .set XT_STK_A11,      52
            .set XT_STK_A12,      56
            .set XT_STK_A13,      60
            .set XT_STK_A14,      64
            .set XT_STK_A15,      68
            .set XT_STK_SAR,      72
            .set XT_STK_EXCCAUSE, 76
            .set XT_STK_EXCVADDR, 80
            .set XT_STK_BASESAVE, 240
            .set XT_STK_FRMSZ,    256

            .macro SAVE_CONTEXT level:req
            mov     a0, a1
            addmi   sp, sp, -XT_STK_FRMSZ
            s32i    a0, sp, +XT_STK_A1
            .ifc \level,double
            rsr     a0, DEPC
            .else
            rsr     a0, EPC\level
            .endif
            s32i    a0, sp, +XT_STK_PC
            .ifc \level,double
            rsr     a0, EXCSAVE2
            .else
            rsr     a0, EXCSAVE\level
            .endif
            s32i    a0, sp, +XT_STK_A0
            .ifc \level,1
            rsr     a0, PS
            s32i    a0, sp, +XT_STK_PS
            rsr     a0, EXCCAUSE
            s32i    a0, sp, +XT_STK_EXCCAUSE
            rsr     a0, EXCVADDR
            s32i    a0, sp, +XT_STK_EXCVADDR
            .endif
            .ifc \level,double
            rsr     a0, EXCCAUSE
            s32i    a0, sp, +XT_STK_EXCCAUSE
            rsr     a0, EXCVADDR
            s32i    a0, sp, +XT_STK_EXCVADDR
            .endif
            call0   save_context
            .endm

            .macro RESTORE_CONTEXT level:req
            call0   restore_context
            .ifc \level,1
            l32i    a0, sp, +XT_STK_PS
            wsr     a0, PS
            l32i    a0, sp, +XT_STK_PC
            wsr     a0, EPC\level
            .endif
            l32i    a0, sp, +XT_STK_A0
            l32i    sp, sp, +XT_STK_A1
            rsync
            .endm

            .endif
            "#,
            $body,
        ))
    };
}

/// Save processor state to stack. *Must only be called with call0.*
/// Saves all registers except PC, PS, A0, A1. A0 = return address, A1 = SP.
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn save_context() {
    naked_ctx_asm!(
        "
        s32i    a2,  sp, +XT_STK_A2
        s32i    a3,  sp, +XT_STK_A3
        s32i    a4,  sp, +XT_STK_A4
        s32i    a5,  sp, +XT_STK_A5
        s32i    a6,  sp, +XT_STK_A6
        s32i    a7,  sp, +XT_STK_A7
        s32i    a8,  sp, +XT_STK_A8
        s32i    a9,  sp, +XT_STK_A9
        s32i    a10, sp, +XT_STK_A10
        s32i    a11, sp, +XT_STK_A11
        s32i    a12, sp, +XT_STK_A12
        s32i    a13, sp, +XT_STK_A13
        s32i    a14, sp, +XT_STK_A14
        s32i    a15, sp, +XT_STK_A15

        rsr     a3,  SAR
        s32i    a3,  sp, +XT_STK_SAR

        ret
    ",
    )
}

/// Restore processor state from stack. *Must only be called with call0.*
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn restore_context() {
    naked_ctx_asm!(
        "
        l32i    a3,  sp, +XT_STK_SAR
        wsr     a3,  SAR

        l32i    a2,  sp, +XT_STK_A2
        l32i    a3,  sp, +XT_STK_A3
        l32i    a4,  sp, +XT_STK_A4
        l32i    a5,  sp, +XT_STK_A5
        l32i    a6,  sp, +XT_STK_A6
        l32i    a7,  sp, +XT_STK_A7
        l32i    a8,  sp, +XT_STK_A8
        l32i    a9,  sp, +XT_STK_A9
        l32i    a10, sp, +XT_STK_A10
        l32i    a11, sp, +XT_STK_A11
        l32i    a12, sp, +XT_STK_A12
        l32i    a13, sp, +XT_STK_A13
        l32i    a14, sp, +XT_STK_A14
        l32i    a15, sp, +XT_STK_A15

        ret
    ",
    )
}

/// Handle Other Exceptions or Level 1 interrupt: store full context, dispatch.
/// A0 stored in EXCSAVE1.
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn __default_naked_exception() {
    naked_ctx_asm!(
        "
        SAVE_CONTEXT 1

        rsr.EXCCAUSE a2                   // put cause in a2
        beqi    a2, 4, .Level1Interrupt   // cause 4 is interrupt

        mov     a3, sp                    // put address of save frame in a3
        call0   __exception               // call handler <= actual call!

        j .RestoreContext

        .Level1Interrupt:
        movi    a2, 1                     // put interrupt level in a2
        mov     a3, sp                    // put address of save frame in a3
        call0   __level_1_interrupt       // call handler <= actual call!

        .RestoreContext:
        RESTORE_CONTEXT 1

        .byte 0x00, 0x30, 0x00            // rfe (not supported in llvm yet)
        ",
    )
}

/// Handle Double Exceptions: store full context, dispatch.
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn __default_naked_double_exception() {
    naked_ctx_asm!(
        "
        SAVE_CONTEXT double

        l32i    a2, sp, +XT_STK_EXCCAUSE  // put cause in a2
        mov     a3, sp                    // put address of save frame in a3
        call0   __double_exception        // call handler <= actual call!

        RESTORE_CONTEXT double

        .byte 0x00, 0x30, 0x00            // rfe
        ",
    )
}

/// Handle Kernel Exceptions: store full context, dispatch. A0 in EXCSAVE1.
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn __default_naked_kernel_exception() {
    naked_ctx_asm!(
        "
        SAVE_CONTEXT 1

        l32i    a2, sp, +XT_STK_EXCCAUSE  // put cause in a2

        mov     a3, sp                    // put address of save frame in a3
        call0   __kernel_exception        // call handler <= actual call!

        RESTORE_CONTEXT 1

        .byte 0x00, 0x30, 0x00            // rfe (PS.EXCM is cleared)
        ",
    )
}

/// Handle NMI Exceptions: store full context, dispatch. A0 in EXCSAVE1.
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn __default_naked_nmi_exception() {
    naked_ctx_asm!(
        "
        SAVE_CONTEXT 1

        l32i    a2, sp, +XT_STK_EXCCAUSE  // put cause in a2

        mov     a3, sp                    // put address of save frame in a3
        call0   __nmi_exception           // call handler <= actual call!

        RESTORE_CONTEXT 1

        .byte 0x00, 0x30, 0x00            // rfe
        ",
    )
}

/// Handle Debug Exceptions: store full context, dispatch. A0 in EXCSAVE1.
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn __default_naked_debug_exception() {
    naked_ctx_asm!(
        "
        SAVE_CONTEXT 1

        l32i    a2, sp, +XT_STK_EXCCAUSE  // put cause in a2

        mov     a3, sp                    // put address of save frame in a3
        call0   __debug_exception         // call handler <= actual call!

        RESTORE_CONTEXT 1

        .byte 0x00, 0x30, 0x00            // rfe
        ",
    )
}

/// Handle Alloc Exceptions: store full context, dispatch. A0 in EXCSAVE1.
#[naked]
#[no_mangle]
#[link_section = ".rwtext"]
unsafe extern "C" fn __default_naked_alloc_exception() {
    naked_ctx_asm!(
        "
        SAVE_CONTEXT 1

        l32i    a2, sp, +XT_STK_EXCCAUSE  // put cause in a2

        mov     a3, sp                    // put address of save frame in a3
        call0   __alloc_exception         // call handler <= actual call!

        RESTORE_CONTEXT 1

        .byte 0x00, 0x30, 0x00            // rfe
        ",
    )
}
