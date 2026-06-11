use std::path::PathBuf;

use xdb::{BreakpointId, BreakpointKind, Stoppoint, Target, VirtAddr, parse};

pub fn handle(target: &mut Target, args: &[&str]) -> xdb::Result<()> {
    match args.get(1).copied() {
        Some("list") => {
            list(target);
            Ok(())
        }
        Some("set") => set(target, args),
        Some(cmd @ ("enable" | "disable" | "delete")) => toggle(target, cmd, args),
        _ => {
            super::print_help(&["help", "breakpoint"]);
            Ok(())
        }
    }
}

fn list(target: &Target) {
    if target.breakpoints().is_empty() {
        println!("No breakpoints set.");
        return;
    }
    println!("Current breakpoints:");
    for bp in target.breakpoints() {
        if bp.is_internal() {
            continue;
        }
        let location = match bp.kind() {
            BreakpointKind::Function(name) => format!("function = {name}"),
            BreakpointKind::Line(file, line) => format!("file = {}, line = {line}", file.display()),
            BreakpointKind::Address(address) => format!("address = {address}"),
        };
        println!(
            "{}: {location}, {}",
            bp.id(),
            if bp.is_enabled() {
                "enabled"
            } else {
                "disabled"
            }
        );
        for &site_id in bp.site_ids() {
            if let Ok(site) = target.process().breakpoint_sites().get_by_id(site_id) {
                println!("    .{site_id}: address = {}", site.address());
            }
        }
    }
}

fn set(target: &mut Target, args: &[&str]) -> xdb::Result<()> {
    let Some(spec) = args.get(2).copied() else {
        super::print_help(&["help", "breakpoint"]);
        return Ok(());
    };
    let hardware = matches!(args.get(3).copied(), Some("-h" | "--hardware"));

    let id = if let Some(address) = spec.strip_prefix("0x") {
        // breakpoint set 0x<address>
        let Some(address) = parse::to_integral::<u64>(address, 16) else {
            eprintln!("Expected a valid hexadecimal address");
            return Ok(());
        };
        target.create_address_breakpoint(VirtAddr(address), hardware, false)?
    } else if let Some((file, line)) = spec.split_once(':') {
        // breakpoint set <file>:<line>
        let Some(line) = parse::to_integral::<u64>(line, 10) else {
            eprintln!("Expected file:line with an integer line");
            return Ok(());
        };
        target.create_line_breakpoint(PathBuf::from(file), line, hardware, false)?
    } else {
        // breakpoint set <function name>
        target.create_function_breakpoint(spec.to_owned(), hardware, false)?
    };

    target.enable_breakpoint(id)
}

fn toggle(target: &mut Target, cmd: &str, args: &[&str]) -> xdb::Result<()> {
    let Some(id) = args
        .get(2)
        .and_then(|s| parse::to_integral::<BreakpointId>(s, 10))
    else {
        eprintln!("Expected a valid breakpoint id");
        return Ok(());
    };
    match cmd {
        "enable" => target.enable_breakpoint(id),
        "disable" => target.disable_breakpoint(id),
        // We only support delete whole logic breakpoint for now
        "delete" => target.remove_breakpoint(id),
        _ => unreachable!(),
    }
}
