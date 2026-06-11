pub mod breakpoint;
pub mod register;

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
        _ => {
            eprintln!("Available commands:");
            eprintln!("    breakpoint  - Commands for operating on breakpoints");
            eprintln!("    continue    - Resume the process");
            eprintln!("    register    - Commands for operating on registers");
            eprintln!("    stepi       - Step a single instruction");
        }
    }
}
