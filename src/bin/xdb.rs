use std::io::{self, BufRead, Write};
use std::path::Path;

use nix::sys::signal::Signal;
use xdb::{Error, Pid, Process, ProcessState, StopReason};

fn main() {
    if let Err(e) = run() {
        eprintln!("xdb: {e}");
        std::process::exit(1);
    }
}

fn run() -> xdb::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let mut process = match args.as_slice() {
        [_, flag, pid] if flag.as_str() == "-p" => {
            let pid: i32 = pid.parse().map_err(|_| Error::new("Invalid PID"))?;
            Process::attach(Pid::from_raw(pid))?
        }
        [_, program] => Process::launch(Path::new(program), true, None)?,
        _ => {
            eprintln!("Usage: xdb <program> | xdb -p <pid>");
            std::process::exit(1);
        }
    };

    println!("Debugging process {}", process.pid());

    let mut stdin = io::stdin().lock();
    let mut line = String::new();
    loop {
        print!("xdb> ");
        io::stdout().flush()?;

        line.clear();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }

        match line.trim() {
            "" => {}
            "quit" | "q" => break,
            command => {
                if let Err(e) = handle_command(&mut process, command) {
                    eprintln!("{e}");
                }
            }
        }
    }

    Ok(())
}

fn handle_command(process: &mut Process, command: &str) -> xdb::Result<()> {
    match command {
        "continue" | "c" => {
            process.resume()?;
            let reason = process.wait_on_signal()?;
            print_stop_reason(process, reason);
            Ok(())
        }
        _ => Err(Error::new(format!("Unknown command: {command}"))),
    }
}

fn print_stop_reason(process: &Process, reason: StopReason) {
    let pid = process.pid();
    match reason.state {
        ProcessState::Stopped => println!(
            "Process {pid} stopped with signal {}",
            signal_name(reason.info)
        ),
        ProcessState::Exited => println!("Process {pid} exited with status {}", reason.info),
        ProcessState::Terminated => println!(
            "Process {pid} terminated with signal {}",
            signal_name(reason.info)
        ),
        ProcessState::Running => {}
    }
}

fn signal_name(info: u8) -> String {
    Signal::try_from(i32::from(info))
        .map_or_else(|_| info.to_string(), |signal| format!("{signal:?}"))
}
