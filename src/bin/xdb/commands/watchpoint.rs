use xdb::{Process, Stoppoint, StoppointMode, VirtAddr, WatchpointId, parse};

pub fn handle(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    match args.get(1).copied() {
        Some("list") => {
            list(process);
            Ok(())
        }
        Some("set") => set(process, args),
        Some(cmd @ ("enable" | "disable" | "delete")) => toggle(process, cmd, args),
        _ => {
            super::print_help(&["help", "watchpoint"]);
            Ok(())
        }
    }
}

fn list(process: &Process) {
    if process.watchpoints().is_empty() {
        println!("No watchpoints set.");
        return;
    }
    println!("Watchpoints:");
    for watchpoint in process.watchpoints().iter() {
        println!(
            "{}: address = {}, mode = {}, size = {}, {}",
            watchpoint.id(),
            watchpoint.address(),
            mode_name(watchpoint.mode()),
            watchpoint.size(),
            if watchpoint.is_enabled() {
                "enabled"
            } else {
                "disabled"
            }
        );
    }
}

fn set(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    let (Some(addr), Some(mode_str), Some(size_str)) = (
        args.get(2).copied(),
        args.get(3).copied(),
        args.get(4).copied(),
    ) else {
        super::print_help(&["help", "watchpoint"]);
        return Ok(());
    };

    let Some(address) = parse::to_integral::<u64>(addr, 16) else {
        eprintln!("Address is expected in 0x... format");
        return Ok(());
    };
    // Parse mode
    let Some(mode) = parse_mode(mode_str) else {
        eprintln!("Invalid mode. Use 'write', 'read_write'/'rw', or 'execute'");
        return Ok(());
    };
    // Parse size
    let Some(size) =
        parse::to_integral::<usize>(size_str, 10).filter(|s| matches!(s, 1 | 2 | 4 | 8))
    else {
        eprintln!("Invalid size. Use 1, 2, 4, or 8");
        return Ok(());
    };

    let id = process.create_watchpoint(VirtAddr(address), mode, size)?;
    process.enable_watchpoint(id)?;
    println!("Watchpoint {id} set at {address:#x}");
    Ok(())
}

fn toggle(process: &mut Process, cmd: &str, args: &[&str]) -> xdb::Result<()> {
    let Some(id) = args
        .get(2)
        .and_then(|s| parse::to_integral::<WatchpointId>(s, 10))
    else {
        eprintln!("Command expects a valid watchpoint id");
        return Ok(());
    };
    match cmd {
        "enable" => process.enable_watchpoint(id),
        "disable" => process.disable_watchpoint(id),
        "delete" => process.remove_watchpoint(id),
        _ => unreachable!(),
    }
}

fn parse_mode(s: &str) -> Option<StoppointMode> {
    match s {
        "write" => Some(StoppointMode::Write),
        "read_write" | "rw" => Some(StoppointMode::ReadWrite),
        "execute" => Some(StoppointMode::Execute),
        _ => None,
    }
}

fn mode_name(mode: StoppointMode) -> &'static str {
    match mode {
        StoppointMode::Write => "write",
        StoppointMode::ReadWrite => "read_write",
        StoppointMode::Execute => "execute",
    }
}
