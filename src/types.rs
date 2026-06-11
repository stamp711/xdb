const WORD_ALIGNMENT_MASK: u64 = 0x7;

/// Virtual address in the debuggee process's address space.
///
/// Represents runtime addresses where code/data actually lives in the running process. Used for
/// ptrace operations, breakpoints, watchpoints, etc. Not tied to any specific ELF - a process may
/// have multiple loaded ELFs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VirtAddr(pub u64);

impl VirtAddr {
    pub fn addr(self) -> u64 {
        self.0
    }

    pub fn align_to_word(self) -> VirtAddr {
        VirtAddr(self.0 & !WORD_ALIGNMENT_MASK)
    }
}

impl std::ops::Add<u64> for VirtAddr {
    type Output = VirtAddr;

    fn add(self, rhs: u64) -> VirtAddr {
        VirtAddr(self.0 + rhs)
    }
}

impl std::ops::Sub<u64> for VirtAddr {
    type Output = VirtAddr;

    fn sub(self, rhs: u64) -> VirtAddr {
        VirtAddr(self.0 - rhs)
    }
}

impl std::fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#x}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoppointMode {
    Execute,
    Write,
    ReadWrite,
}
