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
    /// The register's DWARF number, or None for registers DWARF doesn't name
    /// (sub-registers, segment/debug registers).
    pub dwarf_id: Option<i32>,
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
    ($(($name:ident, $dwarf:expr, $size:expr, $offset:expr, $kind:ident, $format:ident)),* $(,)?) => {
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

registers! {
    // 64-bit general purpose registers and their sub-registers
    (rax, Some(0), 8, gpr!(rax), Gpr, Uint),
    (eax, None, 4, gpr!(rax), SubGpr, Uint),
    (ax, None, 2, gpr!(rax), SubGpr, Uint),
    (al, None, 1, gpr!(rax), SubGpr, Uint),
    (ah, None, 1, gpr_high!(rax), SubGpr, Uint),
    (rdx, Some(1), 8, gpr!(rdx), Gpr, Uint),
    (edx, None, 4, gpr!(rdx), SubGpr, Uint),
    (dx, None, 2, gpr!(rdx), SubGpr, Uint),
    (dl, None, 1, gpr!(rdx), SubGpr, Uint),
    (dh, None, 1, gpr_high!(rdx), SubGpr, Uint),
    (rcx, Some(2), 8, gpr!(rcx), Gpr, Uint),
    (ecx, None, 4, gpr!(rcx), SubGpr, Uint),
    (cx, None, 2, gpr!(rcx), SubGpr, Uint),
    (cl, None, 1, gpr!(rcx), SubGpr, Uint),
    (ch, None, 1, gpr_high!(rcx), SubGpr, Uint),
    (rbx, Some(3), 8, gpr!(rbx), Gpr, Uint),
    (ebx, None, 4, gpr!(rbx), SubGpr, Uint),
    (bx, None, 2, gpr!(rbx), SubGpr, Uint),
    (bl, None, 1, gpr!(rbx), SubGpr, Uint),
    (bh, None, 1, gpr_high!(rbx), SubGpr, Uint),
    (rsi, Some(4), 8, gpr!(rsi), Gpr, Uint),
    (esi, None, 4, gpr!(rsi), SubGpr, Uint),
    (si, None, 2, gpr!(rsi), SubGpr, Uint),
    (sil, None, 1, gpr!(rsi), SubGpr, Uint),
    (rdi, Some(5), 8, gpr!(rdi), Gpr, Uint),
    (edi, None, 4, gpr!(rdi), SubGpr, Uint),
    (di, None, 2, gpr!(rdi), SubGpr, Uint),
    (dil, None, 1, gpr!(rdi), SubGpr, Uint),
    (rbp, Some(6), 8, gpr!(rbp), Gpr, Uint),
    (ebp, None, 4, gpr!(rbp), SubGpr, Uint),
    (bp, None, 2, gpr!(rbp), SubGpr, Uint),
    (bpl, None, 1, gpr!(rbp), SubGpr, Uint),
    (rsp, Some(7), 8, gpr!(rsp), Gpr, Uint),
    (esp, None, 4, gpr!(rsp), SubGpr, Uint),
    (sp, None, 2, gpr!(rsp), SubGpr, Uint),
    (spl, None, 1, gpr!(rsp), SubGpr, Uint),
    (r8, Some(8), 8, gpr!(r8), Gpr, Uint),
    (r8d, None, 4, gpr!(r8), SubGpr, Uint),
    (r8w, None, 2, gpr!(r8), SubGpr, Uint),
    (r8b, None, 1, gpr!(r8), SubGpr, Uint),
    (r9, Some(9), 8, gpr!(r9), Gpr, Uint),
    (r9d, None, 4, gpr!(r9), SubGpr, Uint),
    (r9w, None, 2, gpr!(r9), SubGpr, Uint),
    (r9b, None, 1, gpr!(r9), SubGpr, Uint),
    (r10, Some(10), 8, gpr!(r10), Gpr, Uint),
    (r10d, None, 4, gpr!(r10), SubGpr, Uint),
    (r10w, None, 2, gpr!(r10), SubGpr, Uint),
    (r10b, None, 1, gpr!(r10), SubGpr, Uint),
    (r11, Some(11), 8, gpr!(r11), Gpr, Uint),
    (r11d, None, 4, gpr!(r11), SubGpr, Uint),
    (r11w, None, 2, gpr!(r11), SubGpr, Uint),
    (r11b, None, 1, gpr!(r11), SubGpr, Uint),
    (r12, Some(12), 8, gpr!(r12), Gpr, Uint),
    (r12d, None, 4, gpr!(r12), SubGpr, Uint),
    (r12w, None, 2, gpr!(r12), SubGpr, Uint),
    (r12b, None, 1, gpr!(r12), SubGpr, Uint),
    (r13, Some(13), 8, gpr!(r13), Gpr, Uint),
    (r13d, None, 4, gpr!(r13), SubGpr, Uint),
    (r13w, None, 2, gpr!(r13), SubGpr, Uint),
    (r13b, None, 1, gpr!(r13), SubGpr, Uint),
    (r14, Some(14), 8, gpr!(r14), Gpr, Uint),
    (r14d, None, 4, gpr!(r14), SubGpr, Uint),
    (r14w, None, 2, gpr!(r14), SubGpr, Uint),
    (r14b, None, 1, gpr!(r14), SubGpr, Uint),
    (r15, Some(15), 8, gpr!(r15), Gpr, Uint),
    (r15d, None, 4, gpr!(r15), SubGpr, Uint),
    (r15w, None, 2, gpr!(r15), SubGpr, Uint),
    (r15b, None, 1, gpr!(r15), SubGpr, Uint),
    (rip, Some(16), 8, gpr!(rip), Gpr, Uint),
    (eflags, Some(49), 8, gpr!(eflags), Gpr, Uint),
    (es, Some(50), 8, gpr!(es), Gpr, Uint),
    (cs, Some(51), 8, gpr!(cs), Gpr, Uint),
    (ss, Some(52), 8, gpr!(ss), Gpr, Uint),
    (ds, Some(53), 8, gpr!(ds), Gpr, Uint),
    (fs, Some(54), 8, gpr!(fs), Gpr, Uint),
    (gs, Some(55), 8, gpr!(gs), Gpr, Uint),
    (orig_rax, None, 8, gpr!(orig_rax), Gpr, Uint),

    // x87/SSE control and status registers
    (fcw, Some(65), 2, fpr!(cwd), Fpr, Uint),
    (fsw, Some(66), 2, fpr!(swd), Fpr, Uint),
    (ftw, None, 2, fpr!(ftw), Fpr, Uint),
    (fop, Some(67), 2, fpr!(fop), Fpr, Uint),
    (frip, Some(68), 8, fpr!(rip), Fpr, Uint),
    (frdp, Some(69), 8, fpr!(rdp), Fpr, Uint),
    (mxcsr, Some(64), 4, fpr!(mxcsr), Fpr, Uint),
    (mxcr_mask, None, 4, fpr!(mxcr_mask), Fpr, Uint),

    // x87 stack registers
    (st0, Some(33), 16, st!(0), Fpr, LongDouble),
    (st1, Some(34), 16, st!(1), Fpr, LongDouble),
    (st2, Some(35), 16, st!(2), Fpr, LongDouble),
    (st3, Some(36), 16, st!(3), Fpr, LongDouble),
    (st4, Some(37), 16, st!(4), Fpr, LongDouble),
    (st5, Some(38), 16, st!(5), Fpr, LongDouble),
    (st6, Some(39), 16, st!(6), Fpr, LongDouble),
    (st7, Some(40), 16, st!(7), Fpr, LongDouble),

    // MMX registers (aliased onto the x87 stack)
    (mm0, Some(41), 8, st!(0), Fpr, Vector),
    (mm1, Some(42), 8, st!(1), Fpr, Vector),
    (mm2, Some(43), 8, st!(2), Fpr, Vector),
    (mm3, Some(44), 8, st!(3), Fpr, Vector),
    (mm4, Some(45), 8, st!(4), Fpr, Vector),
    (mm5, Some(46), 8, st!(5), Fpr, Vector),
    (mm6, Some(47), 8, st!(6), Fpr, Vector),
    (mm7, Some(48), 8, st!(7), Fpr, Vector),

    // SSE registers
    (xmm0, Some(17), 16, xmm!(0), Fpr, Vector),
    (xmm1, Some(18), 16, xmm!(1), Fpr, Vector),
    (xmm2, Some(19), 16, xmm!(2), Fpr, Vector),
    (xmm3, Some(20), 16, xmm!(3), Fpr, Vector),
    (xmm4, Some(21), 16, xmm!(4), Fpr, Vector),
    (xmm5, Some(22), 16, xmm!(5), Fpr, Vector),
    (xmm6, Some(23), 16, xmm!(6), Fpr, Vector),
    (xmm7, Some(24), 16, xmm!(7), Fpr, Vector),
    (xmm8, Some(25), 16, xmm!(8), Fpr, Vector),
    (xmm9, Some(26), 16, xmm!(9), Fpr, Vector),
    (xmm10, Some(27), 16, xmm!(10), Fpr, Vector),
    (xmm11, Some(28), 16, xmm!(11), Fpr, Vector),
    (xmm12, Some(29), 16, xmm!(12), Fpr, Vector),
    (xmm13, Some(30), 16, xmm!(13), Fpr, Vector),
    (xmm14, Some(31), 16, xmm!(14), Fpr, Vector),
    (xmm15, Some(32), 16, xmm!(15), Fpr, Vector),

    // Debug registers
    (dr0, None, 8, dr!(0), Dr, Uint),
    (dr1, None, 8, dr!(1), Dr, Uint),
    (dr2, None, 8, dr!(2), Dr, Uint),
    (dr3, None, 8, dr!(3), Dr, Uint),
    (dr4, None, 8, dr!(4), Dr, Uint),
    (dr5, None, 8, dr!(5), Dr, Uint),
    (dr6, None, 8, dr!(6), Dr, Uint),
    (dr7, None, 8, dr!(7), Dr, Uint),
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
    REGISTER_INFOS
        .iter()
        .find(|info| info.dwarf_id == Some(dwarf_id))
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
