pub mod breakpoint;
pub mod disassemble;
pub mod memory;
pub mod register;
pub mod watchpoint;

pub fn print_help(args: &[&str]) {
    match args.get(1).copied() {
        Some("register") => {
            eprintln!("Available register commands:");
            eprintln!("    read");
            eprintln!("    read <register>");
            eprintln!("    read all");
            eprintln!("    write <register> <value>");
        }
        Some("breakpoint") => {
            eprintln!("Available breakpoint commands:");
            eprintln!("    list");
            eprintln!("    set <address>");
            eprintln!("    enable <id>");
            eprintln!("    disable <id>");
            eprintln!("    delete <id>");
        }
        Some("memory") => {
            eprintln!("Available memory commands:");
            eprintln!("    read <address> [count]");
            eprintln!("    write <address> [0xff,0x00,...]");
        }
        Some("watchpoint") => {
            eprintln!("Available watchpoint commands:");
            eprintln!("    list");
            eprintln!("    set <address> <write|rw|execute> <size>");
            eprintln!("    enable <id>");
            eprintln!("    disable <id>");
            eprintln!("    delete <id>");
        }
        _ => {
            eprintln!("Available commands:");
            eprintln!("    breakpoint  - Commands for operating on breakpoints");
            eprintln!("    continue    - Resume the process");
            eprintln!("    disassemble - Disassemble instructions");
            eprintln!("    memory      - Commands for operating on memory");
            eprintln!("    register    - Commands for operating on registers");
            eprintln!("    stepi       - Step a single instruction");
            eprintln!("    watchpoint  - Commands for operating on watchpoints");
        }
    }
}
