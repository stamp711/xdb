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
