use xdb::{Process, VirtAddr, parse};

pub fn handle(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    match args.get(1).copied() {
        Some("read") => read(process, args),
        Some("write") => write(process, args),
        _ => {
            super::print_help(&["help", "memory"]);
            Ok(())
        }
    }
}

fn read(process: &Process, args: &[&str]) -> xdb::Result<()> {
    const DEFAULT_BYTES: usize = 32;
    const BYTES_PER_LINE: usize = 16;

    let Some(address) = args.get(2).and_then(|s| parse::to_integral::<u64>(s, 16)) else {
        eprintln!("Invalid address format. Use 0x prefix for hex addresses.");
        return Ok(());
    };
    let size = match args.get(3) {
        Some(s) => match parse::to_integral::<usize>(s, 10) {
            Some(n) => n,
            None => {
                eprintln!("Invalid size value.");
                return Ok(());
            }
        },
        None => DEFAULT_BYTES, // Default size
    };

    let data = process.read_memory(VirtAddr(address), size)?;
    // Print in hex dump format (16 bytes per line, no ASCII)
    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        // Print hex bytes (max 16 per line)
        let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        println!(
            "{:#016x}: {}",
            address + (i * BYTES_PER_LINE) as u64,
            hex.join(" ")
        );
    }
    Ok(())
}

fn write(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    let Some(address) = args.get(2).and_then(|s| parse::to_integral::<u64>(s, 16)) else {
        eprintln!("Invalid address format. Use 0x prefix for hex addresses.");
        return Ok(());
    };
    let Some(spec) = args.get(3).copied() else {
        super::print_help(&["help", "memory"]);
        return Ok(());
    };
    let bytes = parse::parse_vector(spec)?;
    process.write_memory(VirtAddr(address), &bytes)?;
    println!("Wrote {} bytes to {:#x}", bytes.len(), address);
    Ok(())
}
