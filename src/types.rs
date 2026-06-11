//! Core address types for the debugger.
//!
//! # Address Spaces
//!
//! The debugger deals with multiple address spaces:
//!
//! ```text
//!                     Debuggee Process
//!                     ┌─────────────────────────┐
//!    VirtAddr ───────►│  Running program memory │
//!                     │  (ptrace read/write)    │
//!                     └─────────────────────────┘
//!                               ▲
//!                               │ + load_bias
//!                               │
//!                     ┌─────────────────────────┐
//!    FileAddr ───────►│  ELF virtual addresses  │
//!                     │  (sh_addr, st_value)    │
//!                     └─────────────────────────┘
//!
//!                     ┌─────────────────────────┐
//!    file offset ────►│  Offset in ELF file     │
//!                     │  (sh_offset)            │
//!                     └─────────────────────────┘
//!                               │
//!                               │ + mmap base
//!                               ▼
//!                     ┌─────────────────────────┐
//!    &[u8] ──────────►│  Debugger's mmap'd ELF  │
//!                     └─────────────────────────┘
//! ```
//!
//! - `VirtAddr`: Runtime address in debuggee. Not tied to any ELF.
//! - `FileAddr`: Static address from ELF.
//! - file offset: Byte offset in the ELF file (a plain `usize` index into the mmap).
//! - `&[u8]`: The debugger's mmapped ELF data.

const WORD_ALIGNMENT_MASK: u64 = 0x7;

/// Virtual address in the debuggee process's address space.
///
/// Represents runtime addresses where code/data actually lives in the running process. Used for
/// ptrace operations, breakpoints, watchpoints, etc. Not tied to any specific ELF - a process may
/// have multiple loaded ELFs. To convert to a `FileAddr`, the target ELF must be specified.
///
/// See also [`FileAddr`] for static addresses from ELF files.
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

/// Virtual address as specified in an ELF file (pre-relocation).
///
/// Represents addresses found in ELF metadata: symbol values (st_value), section virtual addresses
/// (sh_addr), DWARF debug info, etc. To get the runtime address in the debuggee process, convert to
/// a `VirtAddr` by adding the load bias.
///
/// This is a bare offset carrying no ELF identity, so it is only meaningful alongside the ELF it
/// came from. With a single loaded object that context is implicit; multiple ELFs (shared
/// libraries) will need a module dimension supplied at the call site (gimli-style: dispatch by
/// module, not an ELF reference stored in the address).
///
/// See also [`VirtAddr`] for runtime addresses in the debuggee process.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileAddr(pub u64);

impl FileAddr {
    pub fn addr(self) -> u64 {
        self.0
    }
}

impl std::ops::Add<u64> for FileAddr {
    type Output = FileAddr;

    fn add(self, rhs: u64) -> FileAddr {
        FileAddr(self.0 + rhs)
    }
}

impl std::ops::Sub<u64> for FileAddr {
    type Output = FileAddr;

    fn sub(self, rhs: u64) -> FileAddr {
        FileAddr(self.0 - rhs)
    }
}

impl std::fmt::Display for FileAddr {
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
