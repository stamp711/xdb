mod commands;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};

use nix::sys::signal::{SigHandler, Signal};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use xdb::{Error, Pid, ProcessState, StopReason, Target};

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

fn handle_stop(target: &Target, reason: StopReason) {
    let pid = target.process().pid();
    match reason.state {
        ProcessState::Stopped => {
            println!(
                "Process {pid} stopped with signal {}",
                signal_name(reason.info)
            );
            if let Some(entry) = target.line_entry_at_pc()
                && let Some(file) = target.source_file_at_pc()
            {
                print_source(&file, entry.line, 3);
            }
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
