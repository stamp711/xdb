use std::mem::offset_of;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterKind {
    Gpr,
    SubGpr,
    Fpr,
    Dr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegisterFormat {
    Uint,
    DoubleFloat,
    LongDouble,
    Vector,
}

#[derive(Debug)]
pub struct RegisterInfo {
    pub id: RegisterId,
    pub name: &'static str,
    /// The register's DWARF number, or -1 for registers DWARF doesn't name
    /// (sub-registers, segment/debug registers).
    pub dwarf_id: i32,
    pub size: usize,
    /// Byte offset of the register within the `user` area.
    pub offset: usize,
    pub kind: RegisterKind,
    pub format: RegisterFormat,
}

impl AsRef<RegisterInfo> for RegisterInfo {
    fn as_ref(&self) -> &RegisterInfo {
        self
    }
}

// Sub-registers alias their parent's storage: `eax`/`ax`/`al` all sit at `rax`'s
// offset and differ only in size. High-byte registers (`ah`, ...) start one
// byte further in.
macro_rules! gpr {
    ($field:ident) => {
        offset_of!(libc::user, regs) + offset_of!(libc::user_regs_struct, $field)
    };
}

macro_rules! gpr_high {
    ($field:ident) => {
        gpr!($field) + 1
    };
}

macro_rules! fpr {
    ($field:ident) => {
        offset_of!(libc::user, i387) + offset_of!(libc::user_fpregs_struct, $field)
    };
}

macro_rules! st {
    ($n:literal) => {
        fpr!(st_space) + $n * 16
    };
}

macro_rules! xmm {
    ($n:literal) => {
        fpr!(xmm_space) + $n * 16
    };
}

macro_rules! dr {
    ($n:literal) => {
        offset_of!(libc::user, u_debugreg) + $n * 8
    };
}

macro_rules! registers {
    ($(($name:ident, $dwarf:literal, $size:expr, $offset:expr, $kind:ident, $format:ident)),* $(,)?) => {
        #[expect(non_camel_case_types)]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum RegisterId { $($name),* }

        pub static REGISTER_INFOS: &[RegisterInfo] = &[
            $(RegisterInfo {
                id: RegisterId::$name,
                name: stringify!($name),
                dwarf_id: $dwarf,
                size: $size,
                offset: $offset,
                kind: RegisterKind::$kind,
                format: RegisterFormat::$format,
            }),*
        ];
    };
}

#[rustfmt::skip]
registers! {
    // 64-bit general purpose registers and their sub-registers
    (rax, 0, 8, gpr!(rax), Gpr, Uint),
    (eax, -1, 4, gpr!(rax), SubGpr, Uint),
    (ax, -1, 2, gpr!(rax), SubGpr, Uint),
    (al, -1, 1, gpr!(rax), SubGpr, Uint),
    (ah, -1, 1, gpr_high!(rax), SubGpr, Uint),
    (rdx, 1, 8, gpr!(rdx), Gpr, Uint),
    (edx, -1, 4, gpr!(rdx), SubGpr, Uint),
    (dx, -1, 2, gpr!(rdx), SubGpr, Uint),
    (dl, -1, 1, gpr!(rdx), SubGpr, Uint),
    (dh, -1, 1, gpr_high!(rdx), SubGpr, Uint),
    (rcx, 2, 8, gpr!(rcx), Gpr, Uint),
    (ecx, -1, 4, gpr!(rcx), SubGpr, Uint),
    (cx, -1, 2, gpr!(rcx), SubGpr, Uint),
    (cl, -1, 1, gpr!(rcx), SubGpr, Uint),
    (ch, -1, 1, gpr_high!(rcx), SubGpr, Uint),
    (rbx, 3, 8, gpr!(rbx), Gpr, Uint),
    (ebx, -1, 4, gpr!(rbx), SubGpr, Uint),
    (bx, -1, 2, gpr!(rbx), SubGpr, Uint),
    (bl, -1, 1, gpr!(rbx), SubGpr, Uint),
    (bh, -1, 1, gpr_high!(rbx), SubGpr, Uint),
    (rsi, 4, 8, gpr!(rsi), Gpr, Uint),
    (esi, -1, 4, gpr!(rsi), SubGpr, Uint),
    (si, -1, 2, gpr!(rsi), SubGpr, Uint),
    (sil, -1, 1, gpr!(rsi), SubGpr, Uint),
    (rdi, 5, 8, gpr!(rdi), Gpr, Uint),
    (edi, -1, 4, gpr!(rdi), SubGpr, Uint),
    (di, -1, 2, gpr!(rdi), SubGpr, Uint),
    (dil, -1, 1, gpr!(rdi), SubGpr, Uint),
    (rbp, 6, 8, gpr!(rbp), Gpr, Uint),
    (ebp, -1, 4, gpr!(rbp), SubGpr, Uint),
    (bp, -1, 2, gpr!(rbp), SubGpr, Uint),
    (bpl, -1, 1, gpr!(rbp), SubGpr, Uint),
    (rsp, 7, 8, gpr!(rsp), Gpr, Uint),
    (esp, -1, 4, gpr!(rsp), SubGpr, Uint),
    (sp, -1, 2, gpr!(rsp), SubGpr, Uint),
    (spl, -1, 1, gpr!(rsp), SubGpr, Uint),
    (r8, 8, 8, gpr!(r8), Gpr, Uint),
    (r8d, -1, 4, gpr!(r8), SubGpr, Uint),
    (r8w, -1, 2, gpr!(r8), SubGpr, Uint),
    (r8b, -1, 1, gpr!(r8), SubGpr, Uint),
    (r9, 9, 8, gpr!(r9), Gpr, Uint),
    (r9d, -1, 4, gpr!(r9), SubGpr, Uint),
    (r9w, -1, 2, gpr!(r9), SubGpr, Uint),
    (r9b, -1, 1, gpr!(r9), SubGpr, Uint),
    (r10, 10, 8, gpr!(r10), Gpr, Uint),
    (r10d, -1, 4, gpr!(r10), SubGpr, Uint),
    (r10w, -1, 2, gpr!(r10), SubGpr, Uint),
    (r10b, -1, 1, gpr!(r10), SubGpr, Uint),
    (r11, 11, 8, gpr!(r11), Gpr, Uint),
    (r11d, -1, 4, gpr!(r11), SubGpr, Uint),
    (r11w, -1, 2, gpr!(r11), SubGpr, Uint),
    (r11b, -1, 1, gpr!(r11), SubGpr, Uint),
    (r12, 12, 8, gpr!(r12), Gpr, Uint),
    (r12d, -1, 4, gpr!(r12), SubGpr, Uint),
    (r12w, -1, 2, gpr!(r12), SubGpr, Uint),
    (r12b, -1, 1, gpr!(r12), SubGpr, Uint),
    (r13, 13, 8, gpr!(r13), Gpr, Uint),
    (r13d, -1, 4, gpr!(r13), SubGpr, Uint),
    (r13w, -1, 2, gpr!(r13), SubGpr, Uint),
    (r13b, -1, 1, gpr!(r13), SubGpr, Uint),
    (r14, 14, 8, gpr!(r14), Gpr, Uint),
    (r14d, -1, 4, gpr!(r14), SubGpr, Uint),
    (r14w, -1, 2, gpr!(r14), SubGpr, Uint),
    (r14b, -1, 1, gpr!(r14), SubGpr, Uint),
    (r15, 15, 8, gpr!(r15), Gpr, Uint),
    (r15d, -1, 4, gpr!(r15), SubGpr, Uint),
    (r15w, -1, 2, gpr!(r15), SubGpr, Uint),
    (r15b, -1, 1, gpr!(r15), SubGpr, Uint),
    (rip, 16, 8, gpr!(rip), Gpr, Uint),
    (eflags, 49, 8, gpr!(eflags), Gpr, Uint),
    (es, 50, 8, gpr!(es), Gpr, Uint),
    (cs, 51, 8, gpr!(cs), Gpr, Uint),
    (ss, 52, 8, gpr!(ss), Gpr, Uint),
    (ds, 53, 8, gpr!(ds), Gpr, Uint),
    (fs, 54, 8, gpr!(fs), Gpr, Uint),
    (gs, 55, 8, gpr!(gs), Gpr, Uint),
    (orig_rax, -1, 8, gpr!(orig_rax), Gpr, Uint),

    // x87/SSE control and status registers
    (fcw, 65, 2, fpr!(cwd), Fpr, Uint),
    (fsw, 66, 2, fpr!(swd), Fpr, Uint),
    (ftw, -1, 2, fpr!(ftw), Fpr, Uint),
    (fop, 67, 2, fpr!(fop), Fpr, Uint),
    (frip, 68, 8, fpr!(rip), Fpr, Uint),
    (frdp, 69, 8, fpr!(rdp), Fpr, Uint),
    (mxcsr, 64, 4, fpr!(mxcsr), Fpr, Uint),
    (mxcr_mask, -1, 4, fpr!(mxcr_mask), Fpr, Uint),

    // x87 stack registers
    (st0, 33, 16, st!(0), Fpr, LongDouble),
    (st1, 34, 16, st!(1), Fpr, LongDouble),
    (st2, 35, 16, st!(2), Fpr, LongDouble),
    (st3, 36, 16, st!(3), Fpr, LongDouble),
    (st4, 37, 16, st!(4), Fpr, LongDouble),
    (st5, 38, 16, st!(5), Fpr, LongDouble),
    (st6, 39, 16, st!(6), Fpr, LongDouble),
    (st7, 40, 16, st!(7), Fpr, LongDouble),

    // MMX registers (aliased onto the x87 stack)
    (mm0, 41, 8, st!(0), Fpr, Vector),
    (mm1, 42, 8, st!(1), Fpr, Vector),
    (mm2, 43, 8, st!(2), Fpr, Vector),
    (mm3, 44, 8, st!(3), Fpr, Vector),
    (mm4, 45, 8, st!(4), Fpr, Vector),
    (mm5, 46, 8, st!(5), Fpr, Vector),
    (mm6, 47, 8, st!(6), Fpr, Vector),
    (mm7, 48, 8, st!(7), Fpr, Vector),

    // SSE registers
    (xmm0, 17, 16, xmm!(0), Fpr, Vector),
    (xmm1, 18, 16, xmm!(1), Fpr, Vector),
    (xmm2, 19, 16, xmm!(2), Fpr, Vector),
    (xmm3, 20, 16, xmm!(3), Fpr, Vector),
    (xmm4, 21, 16, xmm!(4), Fpr, Vector),
    (xmm5, 22, 16, xmm!(5), Fpr, Vector),
    (xmm6, 23, 16, xmm!(6), Fpr, Vector),
    (xmm7, 24, 16, xmm!(7), Fpr, Vector),
    (xmm8, 25, 16, xmm!(8), Fpr, Vector),
    (xmm9, 26, 16, xmm!(9), Fpr, Vector),
    (xmm10, 27, 16, xmm!(10), Fpr, Vector),
    (xmm11, 28, 16, xmm!(11), Fpr, Vector),
    (xmm12, 29, 16, xmm!(12), Fpr, Vector),
    (xmm13, 30, 16, xmm!(13), Fpr, Vector),
    (xmm14, 31, 16, xmm!(14), Fpr, Vector),
    (xmm15, 32, 16, xmm!(15), Fpr, Vector),

    // Debug registers
    (dr0, -1, 8, dr!(0), Dr, Uint),
    (dr1, -1, 8, dr!(1), Dr, Uint),
    (dr2, -1, 8, dr!(2), Dr, Uint),
    (dr3, -1, 8, dr!(3), Dr, Uint),
    (dr4, -1, 8, dr!(4), Dr, Uint),
    (dr5, -1, 8, dr!(5), Dr, Uint),
    (dr6, -1, 8, dr!(6), Dr, Uint),
    (dr7, -1, 8, dr!(7), Dr, Uint),
}

pub const DEBUG_REGISTER_IDS: [RegisterId; 8] = [
    RegisterId::dr0,
    RegisterId::dr1,
    RegisterId::dr2,
    RegisterId::dr3,
    RegisterId::dr4,
    RegisterId::dr5,
    RegisterId::dr6,
    RegisterId::dr7,
];

impl RegisterId {
    pub fn info(self) -> &'static RegisterInfo {
        &REGISTER_INFOS[self as usize]
    }
}

impl AsRef<RegisterInfo> for RegisterId {
    fn as_ref(&self) -> &RegisterInfo {
        self.info()
    }
}

pub fn register_info_by_name(name: &str) -> Option<&'static RegisterInfo> {
    REGISTER_INFOS.iter().find(|info| info.name == name)
}

pub fn register_info_by_dwarf_id(dwarf_id: i32) -> Option<&'static RegisterInfo> {
    REGISTER_INFOS.iter().find(|info| info.dwarf_id == dwarf_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_order_matches_enum_discriminants() {
        for (index, info) in REGISTER_INFOS.iter().enumerate() {
            assert_eq!(info.id as usize, index, "{} out of order", info.name);
        }
    }

    #[test]
    fn lookups_work() {
        assert_eq!(register_info_by_name("rsi").unwrap().id, RegisterId::rsi);
        assert_eq!(register_info_by_dwarf_id(16).unwrap().id, RegisterId::rip);
        assert_eq!(
            RegisterId::ah.info().offset,
            RegisterId::al.info().offset + 1
        );
    }
}
