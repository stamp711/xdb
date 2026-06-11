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
        _ => {
            eprintln!("Available commands:");
            eprintln!("    continue    - Resume the process");
            eprintln!("    register    - Commands for operating on registers");
        }
    }
}
