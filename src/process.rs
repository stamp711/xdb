use std::ffi::CString;
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use nix::errno::Errno;
use nix::sys::personality::{self, Persona};
use nix::sys::ptrace;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{self, ForkResult, Pid};

use crate::breakpoint::{BreakpointSite, SiteId};
use crate::debug_register;
use crate::error::{ErrnoContext, Error, Result};
use crate::inferior;
use crate::pipe::Pipe;
use crate::register_info::{DEBUG_REGISTER_IDS, RegisterId, RegisterInfo, RegisterKind};
use crate::registers::{RegisterValue, Registers, USER_I387_OFFSET, USER_REGS_OFFSET};
use crate::stoppoint::{Stoppoint, StoppointCollection};
use crate::types::{StoppointMode, VirtAddr};
use crate::watchpoint::{Watchpoint, WatchpointId};

const INT3: u8 = 0xCC;

/// Which hardware stoppoint a debug-register trap belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareStop {
    Breakpoint(SiteId),
    Watchpoint(WatchpointId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Stopped,
    Exited,
    Terminated,
}

#[derive(Clone, Debug, derive_more::IsVariant)]
pub enum TrapType {
    Unknown,
    SingleStep,
    SoftwareBreakpoint(Option<SiteId>),
    HardwareStoppoint(Option<HardwareStop>),
    Syscall(SyscallInformation),
}

impl TrapType {
    pub fn is_breakpoint(&self) -> bool {
        matches!(
            self,
            TrapType::SoftwareBreakpoint(..) | TrapType::HardwareStoppoint(..)
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SyscallInformation {
    pub id: u64,
    pub is_entry: bool,
    pub args: Option<[u64; 6]>,
    pub ret: Option<i64>,
}

#[derive(Clone, Debug, derive_more::IsVariant)]
pub enum StopReason {
    Exited(i32),
    Terminated(Signal),
    Stopped(Signal),
    Trapped(TrapType),
}

impl StopReason {
    /// A synthetic single-step stop, used when stepping is simulated without
    /// actually resuming the inferior (e.g. stepping through inlined frames).
    pub fn new_for_single_step() -> Self {
        Self::Trapped(TrapType::SingleStep)
    }

    pub fn is_step(&self) -> bool {
        matches!(self, Self::Trapped(TrapType::SingleStep))
    }

    pub fn is_breakpoint(&self) -> bool {
        matches!(self, Self::Trapped(t) if t.is_breakpoint())
    }

    /// The process phase implied by this stop event.
    pub fn process_state(&self) -> ProcessState {
        match self {
            Self::Exited(_) => ProcessState::Exited,
            Self::Terminated(_) => ProcessState::Terminated,
            Self::Stopped(_) | Self::Trapped(_) => ProcessState::Stopped,
        }
    }
}

/// Which syscalls a syscall catchpoint should stop on.
#[derive(Clone, Debug, Default)]
pub enum SyscallCatchPolicy {
    #[default]
    None,
    Some(std::collections::HashSet<u64>),
    All,
}

impl SyscallCatchPolicy {
    fn catches_none(&self) -> bool {
        matches!(self, Self::None) || matches!(self, Self::Some(ids) if ids.is_empty())
    }

    fn catches(&self, id: u64) -> bool {
        matches!(self, Self::All) || matches!(self, Self::Some(ids) if ids.contains(&id))
    }
}

fn set_ptrace_options(pid: Pid) -> Result<()> {
    // PTRACE_O_TRACESYSGOOD makes the kernel set bit 7 of the signal number on syscall-stops
    // (delivering SIGTRAP|0x80), so the tracer can tell syscall traps from ordinary SIGTRAPs.
    ptrace::setoptions(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)
        .context("PTRACE_SETOPTIONS failed")
}

fn errno_message(prefix: &str, errno: Errno) -> String {
    format!("{prefix}: {}", errno.desc())
}

fn exit_with_message(pipe: &mut Pipe, message: String) -> ! {
    let _ = pipe.write(message.as_bytes());
    pipe.close_write();
    std::process::exit(-1)
}

pub struct Process {
    pid: Pid,
    terminate_on_destruction: bool,
    is_attached: bool,
    state: ProcessState,
    registers: Registers,
    breakpoint_sites: StoppointCollection<BreakpointSite>,
    next_site_id: SiteId,
    watchpoints: StoppointCollection<Watchpoint>,
    next_watchpoint_id: WatchpointId,
    syscall_catch_policy: SyscallCatchPolicy,
    expecting_syscall_exit: bool,
}

impl Process {
    pub fn launch(
        path: &Path,
        debug: bool,
        stdout_replacement: Option<BorrowedFd<'_>>,
    ) -> Result<Self> {
        let path_cstr = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::new("Path contains a nul byte"))?;

        // Close-on-exec so the write end is gone once the child execs:
        // the parent's read() then sees EOF if (and only if) exec succeeded.
        let mut pipe = Pipe::new(true)?;

        // SAFETY: the child only calls async-signal-safe functions before exec.
        let fork_result = unsafe { unistd::fork() }.context("fork failed")?;

        let child = match fork_result {
            ForkResult::Child => {
                pipe.close_read();

                // Put the child in its own process group so the debugger's terminal signals
                // (e.g. Ctrl-C) don't reach it directly.
                if let Err(errno) = unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0)) {
                    exit_with_message(&mut pipe, errno_message("setpgid failed", errno));
                }

                // Disable ASLR so runtime addresses match the ELF across runs.
                let _ = personality::set(Persona::ADDR_NO_RANDOMIZE);

                if let Some(fd) = stdout_replacement
                    && let Err(errno) = unistd::dup2_stdout(fd)
                {
                    exit_with_message(&mut pipe, errno_message("dup2 failed for stdout", errno));
                }

                // Request tracing before exec; the exec itself then raises the initial SIGTRAP
                // that the parent waits on.
                if debug && let Err(errno) = ptrace::traceme() {
                    exit_with_message(&mut pipe, errno_message("PTRACE_TRACEME failed", errno));
                }

                let errno = unistd::execvp(&path_cstr, &[path_cstr.as_c_str()]).unwrap_err();
                // Only reached if exec failed: report the reason up the pipe.
                exit_with_message(&mut pipe, errno_message("Exec failed", errno));
            }
            ForkResult::Parent { child } => child,
        };

        // Drop our write end so read() can reach EOF, then read any error the child sent
        // before exec.
        pipe.close_write();
        let data = pipe.read()?;
        pipe.close_read();

        if !data.is_empty() {
            let _ = waitpid(child, None);
            return Err(Error::new(format!(
                "Child process error: {}",
                String::from_utf8_lossy(&data)
            )));
        }

        let mut process = Self {
            pid: child,
            terminate_on_destruction: true,
            is_attached: debug,
            state: ProcessState::Stopped,
            registers: Registers::new(),
            breakpoint_sites: StoppointCollection::default(),
            next_site_id: 1,
            watchpoints: StoppointCollection::default(),
            next_watchpoint_id: 1,
            syscall_catch_policy: SyscallCatchPolicy::default(),
            expecting_syscall_exit: false,
        };

        if debug {
            process.wait_on_signal()?;
            set_ptrace_options(process.pid)?;
        }

        Ok(process)
    }

    pub fn attach(pid: Pid) -> Result<Self> {
        if pid.as_raw() <= 0 {
            return Err(Error::new("Invalid PID"));
        }

        ptrace::attach(pid).context("PTRACE_ATTACH failed")?;

        let mut process = Self {
            pid,
            terminate_on_destruction: false,
            is_attached: true,
            state: ProcessState::Stopped,
            registers: Registers::new(),
            breakpoint_sites: StoppointCollection::default(),
            next_site_id: 1,
            watchpoints: StoppointCollection::default(),
            next_watchpoint_id: 1,
            syscall_catch_policy: SyscallCatchPolicy::default(),
            expecting_syscall_exit: false,
        };
        process.wait_on_signal()?;
        set_ptrace_options(pid)?;

        Ok(process)
    }

    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn state(&self) -> ProcessState {
        self.state
    }

    pub fn resume(&mut self) -> Result<()> {
        // Single step the breakpoint if it was hit
        let pc = self.get_pc()?;
        if self.breakpoint_sites.enabled_at_address(pc) {
            let id = self.breakpoint_sites.get_by_address(pc)?.id();
            self.disable_breakpoint_site(id)?; // Disable the breakpoint
            // Single step the process
            ptrace::step(self.pid, None).context("PTRACE_SINGLESTEP failed")?;
            // Wait for the process to stop again
            waitpid(self.pid, None).context("waitpid failed")?;
            self.enable_breakpoint_site(id)?; // Re-enable the breakpoint
        }

        // Determine the request based on the syscall catch policy
        if self.syscall_catch_policy.catches_none() {
            ptrace::cont(self.pid, None).context("Could not resume process")?;
        } else {
            ptrace::syscall(self.pid, None).context("Could not resume process")?;
        }
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn step_instruction(&mut self) -> Result<StopReason> {
        // If we are stopped at a breakpoint, restore it to the original instruction
        // before stepping
        let pc = self.get_pc()?;
        let to_reenable = if self.breakpoint_sites.enabled_at_address(pc) {
            Some(self.breakpoint_sites.get_by_address(pc)?.id())
        } else {
            None
        };

        if let Some(id) = to_reenable {
            self.disable_breakpoint_site(id)?;
        }
        ptrace::step(self.pid, None).context("PTRACE_SINGLESTEP failed")?;
        let reason = self.wait_on_signal()?;
        if let Some(id) = to_reenable {
            self.enable_breakpoint_site(id)?;
        }
        Ok(reason)
    }

    /// Resume until the inferior reaches `address`, using a temporary internal
    /// breakpoint if there isn't already one there.
    pub fn run_until_address(&mut self, address: VirtAddr) -> Result<StopReason> {
        let temporary = if self.breakpoint_sites.contains_address(address) {
            None
        } else {
            let id = self.create_breakpoint_site(address, false, true)?;
            self.enable_breakpoint_site(id)?;
            Some(id)
        };

        self.resume()?;
        let mut reason = self.wait_on_signal()?;
        if reason.is_breakpoint() && self.get_pc()? == address {
            reason = StopReason::new_for_single_step();
        }

        if let Some(id) = temporary {
            self.remove_breakpoint_site_by_id(id)?;
        }
        Ok(reason)
    }

    pub fn wait_on_signal(&mut self) -> Result<StopReason> {
        loop {
            let status = waitpid(self.pid, None).context("waitpid failed")?;

            // Only a traced, stopped process can be ptrace-introspected; read its
            // registers up front so classification can consult them.
            if self.is_attached
                && matches!(
                    status,
                    WaitStatus::Stopped(..)
                        | WaitStatus::PtraceEvent(..)
                        | WaitStatus::PtraceSyscall(..)
                )
            {
                self.read_all_registers()?;
            }

            let reason = self.classify_stop(status)?;
            self.state = reason.process_state();

            // Side-effects: certain traps require immediate action before returning.
            match &reason {
                // For a software breakpoint we set, revert pc to the breakpoint address.
                StopReason::Trapped(TrapType::SoftwareBreakpoint(Some(_))) => {
                    let prev_pc = self.get_pc()? - 1;
                    self.set_pc(prev_pc)?;
                }

                // Watchpoint hit: record the data change.
                StopReason::Trapped(TrapType::HardwareStoppoint(Some(
                    HardwareStop::Watchpoint(id),
                ))) => self.update_watchpoint_data(*id)?,

                // A syscall we are not catching: keep running, don't surface this stop.
                StopReason::Trapped(TrapType::Syscall(info))
                    if !self.syscall_catch_policy.catches(info.id) =>
                {
                    self.resume()?;
                    continue;
                }

                _ => {}
            }

            return Ok(reason);
        }
    }

    /// Build the `StopReason` for a `waitpid` result. Assumes registers have
    /// already been read for the stopped cases that inspect them.
    fn classify_stop(&mut self, status: WaitStatus) -> Result<StopReason> {
        Ok(match status {
            WaitStatus::Exited(_, code) => StopReason::Exited(code),
            WaitStatus::Signaled(_, signal, _) => StopReason::Terminated(signal),

            WaitStatus::PtraceSyscall(_) => {
                StopReason::Trapped(TrapType::Syscall(self.read_syscall_information()?))
            }
            WaitStatus::Stopped(_, signal) | WaitStatus::PtraceEvent(_, signal, _) => {
                match signal {
                    Signal::SIGTRAP => StopReason::Trapped(self.classify_sigtrap()?),
                    other => StopReason::Stopped(other),
                }
            }

            _ => StopReason::Trapped(TrapType::Unknown),
        })
    }

    /// Classify a known-SIGTRAP stop from the kernel's `siginfo`.
    fn classify_sigtrap(&self) -> Result<TrapType> {
        let info = inferior::get_signal_info(self.pid)?;
        Ok(match info.si_code {
            libc::TRAP_TRACE => TrapType::SingleStep,
            // x86-64 reports SI_KERNEL for software breakpoints, not TRAP_BRKPT.
            libc::SI_KERNEL => {
                let prev_pc = self.get_pc()? - 1;
                TrapType::SoftwareBreakpoint(self.breakpoint_sites.enabled_id_at_address(prev_pc))
            }
            libc::TRAP_HWBKPT => {
                TrapType::HardwareStoppoint(self.get_current_hardware_stoppoint().ok())
            }
            _ => TrapType::Unknown,
        })
    }

    pub fn registers(&self) -> &Registers {
        &self.registers
    }

    pub fn get_pc(&self) -> Result<VirtAddr> {
        Ok(VirtAddr(self.registers.read_as::<u64>(RegisterId::rip)?))
    }

    pub fn set_pc(&mut self, addr: VirtAddr) -> Result<()> {
        self.write_register_by_id(RegisterId::rip, RegisterValue::U64(addr.addr()))
    }

    pub fn breakpoint_sites(&self) -> &StoppointCollection<BreakpointSite> {
        &self.breakpoint_sites
    }

    pub fn create_breakpoint_site(
        &mut self,
        address: VirtAddr,
        hardware: bool,
        internal: bool,
    ) -> Result<SiteId> {
        if self.breakpoint_sites.contains_address(address) {
            return Err(Error::new(format!(
                "Breakpoint site already created at address {address}"
            )));
        }
        let id = if internal {
            -1
        } else {
            let id = self.next_site_id;
            self.next_site_id += 1;
            id
        };
        self.breakpoint_sites
            .push(BreakpointSite::new(id, address, hardware, internal));
        Ok(id)
    }

    pub fn enable_breakpoint_site(&mut self, id: SiteId) -> Result<()> {
        let site = self.breakpoint_sites.get_by_id(id)?;
        if site.enabled {
            return Ok(());
        }
        let (address, hardware) = (site.address, site.hardware);

        if hardware {
            let slot = self.set_hardware_stoppoint(address, StoppointMode::Execute, 1)?;
            let site = self.breakpoint_sites.get_by_id_mut(id)?;
            site.hardware_register_index = Some(slot);
        } else {
            let original = inferior::replace_byte(self.pid, address.addr(), INT3)?;
            self.breakpoint_sites.get_by_id_mut(id)?.original_byte = original;
        }
        self.breakpoint_sites.get_by_id_mut(id)?.enabled = true;
        Ok(())
    }

    pub fn disable_breakpoint_site(&mut self, id: SiteId) -> Result<()> {
        let site = self.breakpoint_sites.get_by_id(id)?;
        let process_gone = matches!(self.state, ProcessState::Exited | ProcessState::Terminated);
        if !site.enabled || process_gone {
            return Ok(());
        }

        if site.hardware {
            if let Some(slot) = site.hardware_register_index {
                self.clear_hardware_stoppoint(slot)?;
            }
        } else {
            let (address, original) = (site.address.addr(), site.original_byte);
            inferior::replace_byte(self.pid, address, original)?;
        }
        let site = self.breakpoint_sites.get_by_id_mut(id)?;
        site.hardware_register_index = None;
        site.enabled = false;
        Ok(())
    }

    pub fn remove_breakpoint_site_by_id(&mut self, id: SiteId) -> Result<()> {
        self.disable_breakpoint_site(id)?;
        self.breakpoint_sites.remove_by_id(id)?;
        Ok(())
    }

    pub fn remove_breakpoint_site_by_address(&mut self, address: VirtAddr) -> Result<()> {
        let id = self.breakpoint_sites.get_by_address(address)?.id();
        self.remove_breakpoint_site_by_id(id)
    }

    pub fn read_memory(&self, address: VirtAddr, size: usize) -> Result<Vec<u8>> {
        inferior::read_memory(self.pid, address.addr(), size)
    }

    /// Read inferior memory with any software breakpoint bytes replaced by the
    /// original instruction bytes, so the caller never sees `0xCC` patches.
    pub fn read_memory_without_traps(&self, address: VirtAddr, size: usize) -> Result<Vec<u8>> {
        let mut memory = self.read_memory(address, size)?;
        let end = address + size as u64;
        for site in self.breakpoint_sites.get_in_address_range(address, end) {
            if !site.is_enabled() || site.is_hardware() {
                continue;
            }
            let offset = (site.address().addr() - address.addr()) as usize;
            memory[offset] = site.original_byte;
        }
        Ok(memory)
    }

    pub fn write_memory(&mut self, address: VirtAddr, data: &[u8]) -> Result<()> {
        inferior::write_memory(self.pid, address.addr(), data)
    }

    pub fn read_memory_as<T: crate::bit::Pod>(&self, address: VirtAddr) -> Result<T> {
        let data = self.read_memory(address, size_of::<T>())?;
        Ok(crate::bit::from_bytes(&data))
    }

    pub fn watchpoints(&self) -> &StoppointCollection<Watchpoint> {
        &self.watchpoints
    }

    pub fn create_watchpoint(
        &mut self,
        address: VirtAddr,
        mode: StoppointMode,
        size: usize,
    ) -> Result<WatchpointId> {
        if self.watchpoints.contains_address(address) {
            return Err(Error::new(format!(
                "Watchpoint already created at address {address}"
            )));
        }
        // Check address alignment
        if address.addr() & (size as u64 - 1) != 0 {
            return Err(Error::new("Watchpoint address must be aligned to size"));
        }
        let id = self.next_watchpoint_id;
        self.next_watchpoint_id += 1;
        self.watchpoints
            .push(Watchpoint::new(id, address, mode, size));
        self.update_watchpoint_data(id)?;
        Ok(id)
    }

    pub fn enable_watchpoint(&mut self, id: WatchpointId) -> Result<()> {
        let watchpoint = self.watchpoints.get_by_id(id)?;
        if watchpoint.enabled {
            return Ok(());
        }
        let (address, mode, size) = (watchpoint.address, watchpoint.mode, watchpoint.size);
        let slot = self.set_hardware_stoppoint(address, mode, size)?;
        let watchpoint = self.watchpoints.get_by_id_mut(id)?;
        watchpoint.hardware_register_index = Some(slot);
        watchpoint.enabled = true;
        Ok(())
    }

    pub fn disable_watchpoint(&mut self, id: WatchpointId) -> Result<()> {
        let watchpoint = self.watchpoints.get_by_id(id)?;
        let process_gone = matches!(self.state, ProcessState::Exited | ProcessState::Terminated);
        if !watchpoint.enabled || process_gone {
            return Ok(());
        }
        if let Some(slot) = watchpoint.hardware_register_index {
            self.clear_hardware_stoppoint(slot)?;
        }
        let watchpoint = self.watchpoints.get_by_id_mut(id)?;
        watchpoint.hardware_register_index = None;
        watchpoint.enabled = false;
        Ok(())
    }

    pub fn remove_watchpoint(&mut self, id: WatchpointId) -> Result<()> {
        self.disable_watchpoint(id)?;
        self.watchpoints.remove_by_id(id)?;
        Ok(())
    }

    /// Sample the watched memory, rolling the previous value forward.
    pub fn update_watchpoint_data(&mut self, id: WatchpointId) -> Result<()> {
        let (address, size) = {
            let watchpoint = self.watchpoints.get_by_id(id)?;
            (watchpoint.address, watchpoint.size)
        };
        let bytes = self.read_memory(address, size)?;
        let mut new_data = [0u8; 8];
        new_data[..size].copy_from_slice(&bytes[..size]);
        let new_data = u64::from_le_bytes(new_data);

        let watchpoint = self.watchpoints.get_by_id_mut(id)?;
        watchpoint.previous_data = watchpoint.data;
        watchpoint.data = new_data;
        Ok(())
    }

    /// Identify which hardware stoppoint triggered the current trap.
    pub fn get_current_hardware_stoppoint(&self) -> Result<HardwareStop> {
        // Get index of the hit hardware stoppoint from DR6
        let dr6 = self.registers.read_as::<u64>(RegisterId::dr6)?;
        let slot = dr6.trailing_zeros() as usize; // Bit 0-3 encodes the hit hardware stoppoint

        // Get watchpoint address from DR register
        let address = VirtAddr(self.registers.read_as::<u64>(DEBUG_REGISTER_IDS[slot])?);

        // Get watchpoint mode from DR7
        let dr7 = self.registers.read_as::<u64>(RegisterId::dr7)?;
        let mode_bits = (dr7 >> (debug_register::MODE_BITS_OFFSET + 4 * slot)) & 0b11;
        let mode = debug_register::decode_mode(mode_bits)?;

        if mode == StoppointMode::Execute {
            Ok(HardwareStop::Breakpoint(
                self.breakpoint_sites.get_by_address(address)?.id(),
            ))
        } else {
            Ok(HardwareStop::Watchpoint(
                self.watchpoints.get_by_address(address)?.id(),
            ))
        }
    }

    fn set_hardware_stoppoint(
        &mut self,
        address: VirtAddr,
        mode: StoppointMode,
        size: usize,
    ) -> Result<usize> {
        let mode_flag = debug_register::encode_mode(mode);
        let size_flag = debug_register::encode_size(size)?;

        let mut control = self.registers.read_as::<u64>(RegisterId::dr7)?;

        // Find a free slot for the stoppoint
        let slot = debug_register::find_free_slot(control)?;

        // Calculate the control bits locations for the stoppoint
        let enable_bits = 2 * slot;
        let mode_bits = debug_register::MODE_BITS_OFFSET + 4 * slot;
        let size_bits = mode_bits + 2;

        // Calculate the control bits for the stoppoint
        let mask = (0b11 << enable_bits) | (0b11 << mode_bits) | (0b11 << size_bits);
        let flag = (0b01 << enable_bits) | (mode_flag << mode_bits) | (size_flag << size_bits);

        // Set the control bits for the stoppoint
        control = (control & !mask) | flag;

        // Write the address and control bits to the registers
        self.write_register_by_id(DEBUG_REGISTER_IDS[slot], RegisterValue::U64(address.addr()))?;
        self.write_register_by_id(RegisterId::dr7, RegisterValue::U64(control))?;
        Ok(slot)
    }

    fn clear_hardware_stoppoint(&mut self, slot: usize) -> Result<()> {
        let mut control = self.registers.read_as::<u64>(RegisterId::dr7)?;
        // Clear the stoppoint
        control &= !(0b11u64 << (2 * slot));
        self.write_register_by_id(RegisterId::dr7, RegisterValue::U64(control))
    }

    /// Refresh the whole register cache from the inferior. The GPRs and FPRs each come in one
    /// ptrace call, but the debug registers are only reachable individually via the user area.
    fn read_all_registers(&mut self) -> Result<()> {
        let gprs = inferior::read_gprs(self.pid)?;
        let gpr_bytes = crate::bit::as_bytes(&gprs);
        self.registers.data[USER_REGS_OFFSET..USER_REGS_OFFSET + gpr_bytes.len()]
            .copy_from_slice(gpr_bytes);

        let fprs = inferior::read_fprs(self.pid)?;
        let fpr_bytes = crate::bit::as_bytes(&fprs);
        self.registers.data[USER_I387_OFFSET..USER_I387_OFFSET + fpr_bytes.len()]
            .copy_from_slice(fpr_bytes);

        for id in DEBUG_REGISTER_IDS {
            let info = id.info();
            let value = inferior::read_user_area(self.pid, info.offset)?;
            self.registers.data[info.offset..info.offset + 8].copy_from_slice(&value.to_le_bytes());
        }

        Ok(())
    }

    pub fn set_syscall_catch_policy(&mut self, policy: SyscallCatchPolicy) {
        self.syscall_catch_policy = policy;
    }

    /// Read the process's auxiliary vector from `/proc/<pid>/auxv` as a map of
    /// `AT_*` type to value.
    pub fn get_auxv(&self) -> Result<std::collections::HashMap<u64, u64>> {
        let bytes = std::fs::read(format!("/proc/{}/auxv", self.pid))
            .map_err(|e| Error::new(format!("Failed to read auxv: {e}")))?;
        let mut auxv = std::collections::HashMap::new();
        for entry in bytes.chunks_exact(16) {
            let key = u64::from_le_bytes(entry[..8].try_into().unwrap());
            let value = u64::from_le_bytes(entry[8..].try_into().unwrap());
            if key == 0 {
                // AT_NULL marks the end of the auxv
                break;
            }
            auxv.insert(key, value);
        }
        Ok(auxv)
    }

    fn read_syscall_information(&mut self) -> Result<SyscallInformation> {
        let id = self.registers.read_as::<u64>(RegisterId::orig_rax)?;
        if self.expecting_syscall_exit {
            // Syscall exit
            self.expecting_syscall_exit = false;
            let ret = self.registers.read_as::<u64>(RegisterId::rax)? as i64;
            Ok(SyscallInformation {
                id,
                is_entry: false,
                args: None,
                ret: Some(ret),
            })
        } else {
            // Syscall entry
            self.expecting_syscall_exit = true;
            let arg_ids = [
                RegisterId::rdi,
                RegisterId::rsi,
                RegisterId::rdx,
                RegisterId::r10,
                RegisterId::r8,
                RegisterId::r9,
            ];
            let mut args = [0u64; 6];
            for (slot, id) in args.iter_mut().zip(arg_ids) {
                *slot = self.registers.read_as::<u64>(id)?;
            }
            Ok(SyscallInformation {
                id,
                is_entry: true,
                args: Some(args),
                ret: None,
            })
        }
    }

    pub fn write_register(&mut self, info: &RegisterInfo, value: RegisterValue) -> Result<()> {
        // Update the cache, then flush the change back to the inferior.
        self.registers.write(info, value)?;

        if info.kind == RegisterKind::Fpr {
            // POKEUSER can't write the i387 area, so rewrite the whole FPR block.
            let fprs: libc::user_fpregs_struct =
                crate::bit::from_bytes(&self.registers.data[USER_I387_OFFSET..]);
            inferior::write_fprs(self.pid, &fprs)
        } else {
            // POKEUSER writes a whole word, so flush the 8-byte-aligned word the
            // register lives in.
            let aligned = info.offset & !0b111;
            let word = crate::bit::from_bytes::<u64>(&self.registers.data[aligned..]);
            inferior::write_user_area(self.pid, aligned, word)
        }
    }

    pub fn write_register_by_id(&mut self, id: RegisterId, value: RegisterValue) -> Result<()> {
        self.write_register(id.info(), value)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.is_attached {
            // ptrace requires the tracee to be stopped before detaching, so stop it first
            // if it's running, then detach and let it continue.
            if self.state == ProcessState::Running {
                let _ = signal::kill(self.pid, Signal::SIGSTOP);
                let _ = waitpid(self.pid, None);
            }
            let _ = ptrace::detach(self.pid, None);
            let _ = signal::kill(self.pid, Signal::SIGCONT);
        }

        // A process we launched is ours to clean up; one we merely attached to is left running.
        if self.terminate_on_destruction {
            let _ = signal::kill(self.pid, Signal::SIGKILL);
            let _ = waitpid(self.pid, None);
        }
    }
}
