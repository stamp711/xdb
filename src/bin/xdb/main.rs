mod commands;

use std::path::Path;
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::signal::{SigHandler, Signal};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use xdb::{Error, Pid, Process, ProcessState, StopReason};

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

fn attach(args: &[String]) -> xdb::Result<Process> {
    match args {
        [_, flag, pid] if flag.as_str() == "-p" => {
            let pid: i32 = pid.parse().map_err(|_| Error::new("Invalid PID"))?;
            Process::attach(Pid::from_raw(pid))
        }
        [_, program] => Process::launch(Path::new(program), true, None),
        _ => {
            eprintln!("Usage: xdb <program> | xdb -p <pid>");
            std::process::exit(1);
        }
    }
}

fn run() -> xdb::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut process = attach(&args)?;

    INFERIOR_PID.store(process.pid().as_raw(), Ordering::Relaxed);
    // SAFETY: the handler only calls async-signal-safe functions.
    unsafe { nix::sys::signal::signal(Signal::SIGINT, SigHandler::Handler(handle_sigint)) }
        .map_err(|e| Error::new(format!("Failed to install SIGINT handler: {e}")))?;

    println!("Attached to process with PID: {}", process.pid());

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

        if let Err(e) = handle_command(&mut process, command) {
            eprintln!("{e}");
        }
    }

    Ok(())
}

fn handle_command(process: &mut Process, line: &str) -> xdb::Result<()> {
    let args: Vec<&str> = line.split_whitespace().collect();
    let command = args[0];

    match command {
        "continue" | "c" => {
            process.resume()?;
            let reason = process.wait_on_signal()?;
            print_stop_reason(process, reason);
            Ok(())
        }
        "register" | "reg" => commands::register::handle(process, &args),
        "breakpoint" | "b" => commands::breakpoint::handle(process, &args),
        "memory" | "mem" => commands::memory::handle(process, &args),
        "disassemble" | "disas" => commands::disassemble::handle(process, &args),
        "stepi" | "si" => {
            let reason = process.step_instruction()?;
            print_stop_reason(process, reason);
            Ok(())
        }
        "help" | "h" => {
            commands::print_help(&args);
            Ok(())
        }
        _ => Err(Error::new(format!("Unknown command: {command}"))),
    }
}

fn print_stop_reason(process: &Process, reason: StopReason) {
    let pid = process.pid();
    match reason.state {
        ProcessState::Stopped => {
            println!(
                "Process {pid} stopped with signal {}",
                signal_name(reason.info)
            );
        }
        ProcessState::Exited => println!("Process {pid} exited with status {}", reason.info),
        ProcessState::Terminated => {
            println!(
                "Process {pid} terminated with signal {}",
                signal_name(reason.info)
            );
        }
        ProcessState::Running => {}
    }
}

fn signal_name(info: u8) -> String {
    Signal::try_from(i32::from(info))
        .map_or_else(|_| info.to_string(), |signal| format!("{signal:?}"))
}
