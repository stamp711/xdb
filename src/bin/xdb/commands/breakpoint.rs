use xdb::{Process, SiteId, Stoppoint, VirtAddr, parse};

pub fn handle(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    match args.get(1).copied() {
        Some("list") => {
            list(process);
            Ok(())
        }
        Some("set") => set(process, args),
        Some(cmd @ ("enable" | "disable" | "delete")) => toggle(process, cmd, args),
        _ => {
            super::print_help(&["help", "breakpoint"]);
            Ok(())
        }
    }
}

fn list(process: &Process) {
    if process.breakpoint_sites().is_empty() {
        println!("No breakpoint sites set.");
        return;
    }
    println!("Current breakpoint sites:");
    for site in process.breakpoint_sites().iter() {
        println!(
            "{}: address = {}, {}",
            site.id(),
            site.address(),
            if site.is_enabled() {
                "enabled"
            } else {
                "disabled"
            }
        );
    }
}

fn set(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    let Some(spec) = args.get(2).copied() else {
        super::print_help(&["help", "breakpoint"]);
        return Ok(());
    };
    // breakpoint set 0x<address>
    let Some(address) = parse::to_integral::<u64>(spec, 16) else {
        eprintln!("Expected a valid hexadecimal address prefixed with '0x'");
        return Ok(());
    };
    let hardware = matches!(args.get(3).copied(), Some("-h" | "--hardware"));
    let id = process.create_breakpoint_site(VirtAddr(address), hardware, false)?;
    process.enable_breakpoint_site(id)
}

fn toggle(process: &mut Process, cmd: &str, args: &[&str]) -> xdb::Result<()> {
    let Some(id) = args
        .get(2)
        .and_then(|s| parse::to_integral::<SiteId>(s, 10))
    else {
        eprintln!("Expected a valid breakpoint site id");
        return Ok(());
    };
    match cmd {
        "enable" => process.enable_breakpoint_site(id),
        "disable" => process.disable_breakpoint_site(id),
        "delete" => process.remove_breakpoint_site_by_id(id),
        _ => unreachable!(),
    }
}
