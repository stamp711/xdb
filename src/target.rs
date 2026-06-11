use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use nix::unistd::Pid;

use crate::elf::Elf;
use crate::error::{Error, Result};
use crate::process::Process;
use crate::types::VirtAddr;

/// Owns a running process together with the static ELF (and, later, DWARF) of
/// the program it is executing, and coordinates between the two.
pub struct Target {
    process: Process,
    elf: Elf,
}

impl Target {
    pub fn launch(path: &Path, stdout_replacement: Option<BorrowedFd<'_>>) -> Result<Self> {
        let process = Process::launch(path, true, stdout_replacement)?;
        let elf = load_elf(&process, path)?;
        Ok(Self { process, elf })
    }

    pub fn attach(pid: Pid) -> Result<Self> {
        let process = Process::attach(pid)?;
        let exe = PathBuf::from(format!("/proc/{pid}/exe"));
        let elf = load_elf(&process, &exe)?;
        Ok(Self { process, elf })
    }

    pub fn process(&self) -> &Process {
        &self.process
    }

    pub fn process_mut(&mut self) -> &mut Process {
        &mut self.process
    }

    pub fn elf(&self) -> &Elf {
        &self.elf
    }
}

/// Open the ELF and set its load bias from the runtime entry point, found in
/// the auxiliary vector (`AT_ENTRY`).
fn load_elf(process: &Process, path: &Path) -> Result<Elf> {
    let auxv = process.get_auxv()?;
    let mut elf = Elf::new(path)?;
    let entry = auxv
        .get(&(libc::AT_ENTRY))
        .ok_or_else(|| Error::new("AT_ENTRY missing from auxv"))?;
    let load_bias = entry - elf.header().e_entry;
    elf.notify_load_bias(VirtAddr(load_bias));
    Ok(elf)
}
