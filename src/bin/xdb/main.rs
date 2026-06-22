mod commands;

use std::borrow::Cow;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::signal::{SigHandler, Signal};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use xdb::syscalls::syscall_id_to_name;
use xdb::{
    Error, HardwareStop, Pid, Process, ProcessState, StopReason, SyscallInformation, Target,
    TrapType,
};

static INFERIOR_PID: AtomicI32 = AtomicI32::new(0);

extern "C" fn handle_sigint(_: libc::c_int) {
    let pid = INFERIOR_PID.load(Ordering::Relaxed);
    if pid > 0 {
        // SAFETY: kill is async-signal-safe.
        unsafe { libc::kill(pid, libc::SIGSTOP) };
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("xdb: {e}");
        std::process::exit(1);
    }
}

fn attach(args: &[String]) -> xdb::Result<Target> {
    match args {
        [_, flag, pid] if flag.as_str() == "-p" => {
            let pid: i32 = pid.parse().map_err(|_| Error::new("Invalid PID"))?;
            Target::attach(Pid::from_raw(pid))
        }
        [_, program] => Target::launch(Path::new(program), None),
        _ => {
            eprintln!("Usage: xdb <program> | xdb -p <pid>");
            std::process::exit(1);
        }
    }
}

fn run() -> xdb::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut target = attach(&args)?;

    INFERIOR_PID.store(target.process().pid().as_raw(), Ordering::Relaxed);
    // SAFETY: the handler only calls async-signal-safe functions.
    unsafe { nix::sys::signal::signal(Signal::SIGINT, SigHandler::Handler(handle_sigint)) }
        .map_err(|e| Error::new(format!("Failed to install SIGINT handler: {e}")))?;

    println!("Attached to process with PID: {}", target.process().pid());

    let mut editor = DefaultEditor::new().map_err(|e| Error::new(e.to_string()))?;
    let mut last_line = String::new();
    loop {
        let line = match editor.readline("xdb> ") {
            Ok(line) => line,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => break,
            Err(e) => return Err(Error::new(e.to_string())),
        };

        let command = if line.trim().is_empty() {
            last_line.clone()
        } else {
            let _ = editor.add_history_entry(&line);
            last_line = line.clone();
            line
        };

        let command = command.trim();
        if command.is_empty() {
            continue;
        }
        if command == "quit" || command == "q" {
            break;
        }

        if let Err(e) = handle_command(&mut target, command) {
            eprintln!("{e}");
        }
    }

    Ok(())
}

fn handle_command(target: &mut Target, line: &str) -> xdb::Result<()> {
    let args: Vec<&str> = line.split_whitespace().collect();
    let command = args[0];

    match command {
        "continue" | "c" => {
            target.resume()?;
            let reason = target.wait_on_signal()?;
            handle_stop(target, reason);
            Ok(())
        }
        "stepi" | "si" => step(target, Target::step_instruction),
        "step" | "s" => step(target, Target::step_in),
        "next" | "n" => step(target, Target::step_over),
        "finish" => step(target, Target::step_out),
        "breakpoint" | "b" => commands::breakpoint::handle(target, &args),
        "register" | "reg" => commands::register::handle(target.process_mut(), &args),
        "memory" | "mem" => commands::memory::handle(target.process_mut(), &args),
        "disassemble" | "disas" => commands::disassemble::handle(target.process_mut(), &args),
        "watchpoint" | "w" => commands::watchpoint::handle(target.process_mut(), &args),
        "catchpoint" | "catch" => commands::catchpoint::handle(target.process_mut(), &args),
        "help" | "h" => {
            commands::print_help(&args);
            Ok(())
        }
        _ => Err(Error::new(format!("Unknown command: {command}"))),
    }
}

fn step(target: &mut Target, op: fn(&mut Target) -> xdb::Result<StopReason>) -> xdb::Result<()> {
    let reason = op(target)?;
    handle_stop(target, reason);
    Ok(())
}

fn format_syscall_trap_info(syscall: &SyscallInformation) -> String {
    if syscall.is_entry {
        return " (syscall entry)".to_string();
    }
    " (syscall exit)".to_string()
}

fn print_syscall_details(syscall: &SyscallInformation) {
    let syscall_name = syscall_id_to_name(syscall.id).unwrap_or("unknown");

    if syscall.is_entry {
        if let Some(args) = syscall.args {
            println!(
                "syscall entry: {syscall_name}({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})",
                args[0], args[1], args[2], args[3], args[4], args[5]
            );
        } else {
            println!("syscall entry: {syscall_name}(...)");
        }
    } else if let Some(ret) = syscall.ret {
        println!("syscall exit: {syscall_name}(...) = {ret:#x}");
    } else {
        println!("syscall exit: {syscall_name}(...)");
    }
}

fn get_sigtrap_desc(process: &Process, reason: &StopReason) -> Option<Cow<'static, str>> {
    let StopReason::Trapped(trap) = reason else {
        return None;
    };

    match trap {
        TrapType::SingleStep => Some(" (single step)".into()),

        TrapType::SoftwareBreakpoint(Some(site_id)) => {
            Some(format!(" (breakpoint {})", site_id).into())
        }

        TrapType::HardwareStoppoint(Some(HardwareStop::Breakpoint(id))) => {
            Some(format!(" (breakpoint {id})").into())
        }

        TrapType::HardwareStoppoint(Some(HardwareStop::Watchpoint(id))) => {
            let mut message = format!(" (watchpoint {id})");
            if let Ok(wp) = process.watchpoints().get_by_id(*id) {
                if wp.data() == wp.previous_data() {
                    message += &format!("\n Value: {:#x}", wp.data());
                } else {
                    message += &format!("\n Previous Value: {:#x}", wp.previous_data());
                    message += &format!("\n Current Value: {:#x}", wp.data());
                }
            }
            Some(message.into())
        }

        TrapType::Syscall(syscall_info) => Some(format_syscall_trap_info(syscall_info).into()),

        TrapType::Unknown
        | TrapType::SoftwareBreakpoint(None)
        | TrapType::HardwareStoppoint(None) => None,
    }
}

fn generate_signal_stop_reason(target: &Target, reason: &StopReason) -> String {
    // `Trapped` implies SIGTRAP; `Exited`/`Terminated` never reach this "stopped" path.
    let signal = match reason {
        StopReason::Stopped(signal) => *signal,
        StopReason::Trapped(..) => Signal::SIGTRAP,
        _ => unreachable!(),
    };
    let process = target.process();
    let Ok(pc) = process.get_pc() else {
        return format!("stopped by signal {signal:?}");
    };
    let mut message = format!("stopped by signal {signal:?}, {:#x}", pc.addr());

    let location = target.current_location();
    if let Some(func) = location.function.filter(|f| !f.is_empty()) {
        message += &format!(" in {func} ()");
    }
    if let Some(source) = location.source {
        let file = source
            .file
            .path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        message += &format!(" at {file}:{}", source.line);
    }

    if let Some(desc) = get_sigtrap_desc(process, reason) {
        message += &desc;
    }

    message
}

fn print_stop_reason(target: &Target, reason: &StopReason) {
    let message = match reason {
        StopReason::Exited(code) => format!("exited with status {code}"),
        StopReason::Terminated(signal) => format!("terminated by signal {signal:?}"),
        StopReason::Stopped(_) | StopReason::Trapped(_) => {
            generate_signal_stop_reason(target, reason)
        }
    };
    println!("Process {} {}", target.process().pid(), message);

    // Print additional syscall details if this is a syscall trap
    if let StopReason::Trapped(TrapType::Syscall(syscall_info)) = reason {
        print_syscall_details(syscall_info);
    }
}

fn handle_stop(target: &Target, reason: StopReason) {
    print_stop_reason(target, &reason);
    if reason.process_state() == ProcessState::Stopped {
        if let Some(source) = target.current_location().source {
            print_source(&source.file.path, source.line, 3);
        } else {
            let process = target.process();
            let _ = commands::disassemble::print_disassembly(process, process.get_pc().ok(), 5);
        }
    }
}

fn print_source(path: &PathBuf, line: u64, context: u64) {
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    let start = line.saturating_sub(context).max(1);
    let end = line + context;
    for (number, text) in BufReader::new(file)
        .lines()
        .enumerate()
        .map(|(i, l)| (i as u64 + 1, l))
    {
        if number < start {
            continue;
        }
        if number > end {
            break;
        }
        let Ok(text) = text else { break };
        let marker = if number == line { '>' } else { ' ' };
        println!("{marker} {number:>4} {text}");
    }
}
