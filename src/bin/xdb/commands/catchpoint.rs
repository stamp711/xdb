use std::collections::HashSet;

use xdb::syscalls::{syscall_id_to_name, syscall_name_to_id};
use xdb::{Process, SyscallCatchPolicy, parse};

pub fn handle(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    match args.get(1).copied() {
        // Handle "catch syscall" or "catch sys" commands
        Some("syscall" | "sys") => syscall(process, args),
        _ => {
            super::print_help(&["help", "catchpoint"]);
            Ok(())
        }
    }
}

fn syscall(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    match args.get(2).copied() {
        // Both "catch syscall" and "catch sys" with no arguments means catch all syscalls
        None => {
            process.set_syscall_catch_policy(SyscallCatchPolicy::All);
            println!("Now catching all syscalls.");
        }
        // Handle "catch sys none"
        Some("none") => {
            process.set_syscall_catch_policy(SyscallCatchPolicy::None);
            println!("No longer catching any syscalls.");
        }
        // Parse comma-separated syscall identifiers
        Some(list) => {
            let mut ids = HashSet::new();
            for item in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let Some(id) = resolve(item) else {
                    eprintln!("Unknown syscall identifier '{item}'");
                    return Ok(());
                };
                ids.insert(id);
            }
            if ids.is_empty() {
                eprintln!("No valid syscall identifiers provided");
                return Ok(());
            }
            println!("Now catching {} syscall(s):", ids.len());
            for id in &ids {
                let name = syscall_id_to_name(*id).unwrap_or("unknown");
                println!("  {name} ({id})");
            }
            process.set_syscall_catch_policy(SyscallCatchPolicy::Some(ids));
        }
    }
    Ok(())
}

fn resolve(item: &str) -> Option<u64> {
    // Try to parse as number first
    // Try to parse as syscall name
    parse::to_integral::<u64>(item, 10).or_else(|| syscall_name_to_id(item))
}
