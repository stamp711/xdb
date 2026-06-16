mod commands;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::signal::{SigHandler, Signal};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use xdb::syscalls::syscall_id_to_name;
use xdb::{
    Error, HardwareStop, Pid, Process, ProcessState, StopReason, Stoppoint, SyscallInformation,
    Target, TrapType,
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

fn get_sigtrap_info(process: &Process, reason: &StopReason) -> String {
    let mut message = String::new();

    let Some(trap) = reason.trap else {
        return message;
    };
    match trap {
        TrapType::SoftwareBreakpoint => {
            if let Ok(pc) = process.get_pc()
                && let Ok(bp) = process.breakpoint_sites().get_by_address(pc)
            {
                message = format!(" (breakpoint {})", bp.id());
            }
        }
        TrapType::SingleStep => {
            message = " (single step)".to_string();
        }
        TrapType::HardwareStoppoint => match process.get_current_hardware_stoppoint() {
            // Hardware breakpoint
            Ok(HardwareStop::Breakpoint(id)) => {
                message = format!(" (breakpoint {id})");
            }
            // Hardware watchpoint
            Ok(HardwareStop::Watchpoint(watchpoint_id)) => {
                message = format!(" (watchpoint {watchpoint_id})");
                if let Ok(wp) = process.watchpoints().get_by_id(watchpoint_id) {
                    if wp.data() == wp.previous_data() {
                        message += &format!("\n Value: {:#x}", wp.data());
                    } else {
                        message += &format!("\n Previous Value: {:#x}", wp.previous_data());
                        message += &format!("\n Current Value: {:#x}", wp.data());
                    }
                }
            }
            Err(_) => {}
        },
        TrapType::Syscall => {
            if let Some(syscall) = reason.syscall {
                message = format_syscall_trap_info(&syscall);
            } else {
                message = " (syscall)".to_string();
            }
        }
        TrapType::Unknown => {}
    }

    message
}

fn generate_signal_stop_reason(target: &Target, reason: &StopReason) -> String {
    let process = target.process();
    let Ok(pc) = process.get_pc() else {
        return format!("stopped by signal {}", signal_name(reason.info));
    };
    let mut message = format!(
        "stopped by signal {}, {:#x}",
        signal_name(reason.info),
        pc.addr()
    );

    let func_name = target.function_name_at_address(pc);
    if !func_name.is_empty() {
        message += &format!(" in {func_name} ()");
    }

    if let Some(entry) = target.line_entry_at_pc()
        && let Some(file) = target.source_file_at_pc()
    {
        let file = file
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        message += &format!(" at {file}:{}", entry.line);
    }

    if reason.info == Signal::SIGTRAP as u8 {
        message += &get_sigtrap_info(process, reason);
    }

    message
}

fn print_stop_reason(target: &Target, reason: &StopReason) {
    let message = match reason.state {
        ProcessState::Running => "is running".to_string(),
        ProcessState::Stopped => generate_signal_stop_reason(target, reason),
        ProcessState::Exited => format!("exited with status {}", reason.info),
        ProcessState::Terminated => format!("terminated by signal {}", signal_name(reason.info)),
    };
    println!("Process {} {}", target.process().pid(), message);

    // Print additional syscall details if this is a syscall trap
    if reason.state == ProcessState::Stopped
        && reason.info == Signal::SIGTRAP as u8
        && reason.trap == Some(TrapType::Syscall)
        && let Some(syscall) = reason.syscall
    {
        print_syscall_details(&syscall);
    }
}

fn handle_stop(target: &Target, reason: StopReason) {
    print_stop_reason(target, &reason);
    if reason.state == ProcessState::Stopped {
        if target.stack().inline_height() > 0 {
            let die = target.dwarf().die(target.current_frame_of_inline_stack());
            if let (Ok(file), Ok(line)) = (die.file(), die.line()) {
                print_source(&file.path, line, 3);
            }
        } else if let Some(entry) = target.line_entry_at_pc()
            && let Some(file) = target.source_file_at_pc()
        {
            print_source(&file, entry.line, 3);
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

fn signal_name(info: u8) -> String {
    Signal::try_from(i32::from(info))
        .map_or_else(|_| info.to_string(), |signal| format!("{signal:?}"))
}
