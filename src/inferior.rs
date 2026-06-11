//! Raw inferior I/O. Everything here is a function of `Pid` so that callers
//! holding borrows into `Process` state can still drive ptrace.

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::unistd::Pid;

use crate::error::{ErrnoContext, Result};

pub(crate) fn read_gprs(pid: Pid) -> Result<libc::user_regs_struct> {
    ptrace::getregs(pid).context("PTRACE_GETREGS failed")
}

#[expect(dead_code)]
pub(crate) fn write_gprs(pid: Pid, gprs: libc::user_regs_struct) -> Result<()> {
    ptrace::setregs(pid, gprs).context("PTRACE_SETREGS failed")
}

pub(crate) fn read_fprs(pid: Pid) -> Result<libc::user_fpregs_struct> {
    let mut fprs = crate::bit::from_bytes::<libc::user_fpregs_struct>(
        &[0u8; size_of::<libc::user_fpregs_struct>()],
    );
    // SAFETY: PTRACE_GETFPREGS fills exactly one user_fpregs_struct.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_GETFPREGS,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            &raw mut fprs,
        )
    };
    if rc == -1 {
        return Err(Errno::last()).context("PTRACE_GETFPREGS failed");
    }
    Ok(fprs)
}

pub(crate) fn write_fprs(pid: Pid, fprs: &libc::user_fpregs_struct) -> Result<()> {
    // SAFETY: PTRACE_SETFPREGS reads exactly one user_fpregs_struct.
    let rc = unsafe {
        libc::ptrace(
            libc::PTRACE_SETFPREGS,
            pid.as_raw(),
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::from_ref(fprs),
        )
    };
    if rc == -1 {
        return Err(Errno::last()).context("PTRACE_SETFPREGS failed");
    }
    Ok(())
}

pub(crate) fn read_user_area(pid: Pid, offset: usize) -> Result<u64> {
    ptrace::read_user(pid, std::ptr::without_provenance_mut(offset))
        .map(|word| word as u64)
        .context("PTRACE_PEEKUSER failed")
}

pub(crate) fn write_user_area(pid: Pid, offset: usize, data: u64) -> Result<()> {
    ptrace::write_user(
        pid,
        std::ptr::without_provenance_mut(offset),
        data as libc::c_long,
    )
    .context("PTRACE_POKEUSER failed")
}

fn peek_word(pid: Pid, addr: u64) -> Result<u64> {
    ptrace::read(pid, std::ptr::without_provenance_mut(addr as usize))
        .map(|word| word as u64)
        .context("PTRACE_PEEKDATA failed")
}

fn poke_word(pid: Pid, addr: u64, word: u64) -> Result<()> {
    ptrace::write(
        pid,
        std::ptr::without_provenance_mut(addr as usize),
        word as libc::c_long,
    )
    .context("PTRACE_POKEDATA failed")
}

/// Overwrite a single byte in the inferior, returning the byte that was there.
/// Reads and rewrites the containing aligned word so memory protection (e.g.
/// non-writable code pages) does not block the patch.
pub(crate) fn replace_byte(pid: Pid, addr: u64, new_byte: u8) -> Result<u8> {
    let aligned = addr & !0b111;
    let index = (addr - aligned) as usize;

    let mut bytes = peek_word(pid, aligned)?.to_le_bytes();
    let original = bytes[index];
    bytes[index] = new_byte;
    poke_word(pid, aligned, u64::from_le_bytes(bytes))?;

    Ok(original)
}

const PAGE_SIZE: u64 = 0x1000;
const WORD_SIZE: u64 = 8;

pub(crate) fn read_memory(pid: Pid, addr: u64, len: usize) -> Result<Vec<u8>> {
    use nix::sys::uio::{RemoteIoVec, process_vm_readv};

    // Prepare data buffer and local iovec
    let mut data = vec![0u8; len];

    // Allocate remote iovecs for each page
    let mut remote = Vec::new();
    let mut cursor = addr;
    let mut remaining = len as u64;
    while remaining > 0 {
        let to_page_end = PAGE_SIZE - (cursor & (PAGE_SIZE - 1));
        let chunk = remaining.min(to_page_end);
        remote.push(RemoteIoVec {
            base: cursor as usize,
            len: chunk as usize,
        });
        cursor += chunk;
        remaining -= chunk;
    }

    let mut local = [std::io::IoSliceMut::new(&mut data)];
    process_vm_readv(pid, &mut local, &remote).context("process_vm_readv failed")?;
    Ok(data)
}

/// We use PTRACE_POKEDATA here because it can write to PROT_READ or PROT_EXEC (i.e. not writable)
/// memory. However, it can only write exactly 8 bytes at a time.
pub(crate) fn write_memory(pid: Pid, addr: u64, data: &[u8]) -> Result<()> {
    let mut cursor = addr;
    let mut rest = data;
    while !rest.is_empty() {
        // Write one word at a time
        let word_start = cursor & !(WORD_SIZE - 1);
        let offset = (cursor - word_start) as usize; // Offset of addr within the word
        let word_end = word_start + WORD_SIZE;
        let end = word_end.min(cursor + rest.len() as u64);
        let size = (end - cursor) as usize; // size of the data to write in the word

        let mut bytes = if word_start < cursor || end < word_end {
            // Read the original word
            peek_word(pid, word_start)?.to_le_bytes()
        } else {
            [0u8; 8]
        };
        // Copy the data into the word to write
        bytes[offset..offset + size].copy_from_slice(&rest[..size]);
        poke_word(pid, word_start, u64::from_le_bytes(bytes))?;

        cursor = end;
        rest = &rest[size..];
    }
    Ok(())
}
