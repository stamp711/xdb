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

use crate::error::{ErrnoContext, Error, Result};
use crate::inferior;
use crate::pipe::Pipe;
use crate::register_info::{DEBUG_REGISTER_IDS, RegisterId, RegisterInfo, RegisterKind};
use crate::registers::{self, RegisterValue, Registers, USER_I387_OFFSET, USER_REGS_OFFSET};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessState {
    Running,
    Stopped,
    Exited,
    Terminated,
}

#[derive(Clone, Copy, Debug)]
pub struct StopReason {
    pub state: ProcessState,
    pub info: u8,
}

impl From<WaitStatus> for StopReason {
    fn from(status: WaitStatus) -> Self {
        match status {
            WaitStatus::Stopped(_, signal) => Self {
                state: ProcessState::Stopped,
                info: signal as u8,
            },
            WaitStatus::Exited(_, code) => Self {
                state: ProcessState::Exited,
                info: code as u8,
            },
            WaitStatus::Signaled(_, signal, _) => Self {
                state: ProcessState::Terminated,
                info: signal as u8,
            },
            WaitStatus::PtraceEvent(_, signal, _) => Self {
                state: ProcessState::Stopped,
                info: signal as u8,
            },
            WaitStatus::PtraceSyscall(_) => Self {
                state: ProcessState::Stopped,
                info: Signal::SIGTRAP as u8 | 0x80,
            },
            _ => Self {
                state: ProcessState::Stopped,
                info: 0,
            },
        }
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
        ptrace::cont(self.pid, None).context("Could not resume process")?;
        self.state = ProcessState::Running;
        Ok(())
    }

    pub fn wait_on_signal(&mut self) -> Result<StopReason> {
        let status = waitpid(self.pid, None).context("waitpid failed")?;
        let reason = StopReason::from(status);
        self.state = reason.state;

        if self.is_attached && self.state == ProcessState::Stopped {
            self.read_all_registers()?;
        }

        Ok(reason)
    }

    pub fn registers(&self) -> &Registers {
        &self.registers
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

    pub fn write_register(&mut self, info: &RegisterInfo, value: RegisterValue) -> Result<()> {
        // Update the cache, then flush the change back to the inferior.
        let widened = registers::widen(info, value)?;
        self.registers.data[info.offset..info.offset + info.size]
            .copy_from_slice(&widened[..info.size]);

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
