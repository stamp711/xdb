use xdb::{Disassembler, Process, VirtAddr, parse};

const DEFAULT_INSTRUCTION_COUNT: usize = 5;

pub fn handle(process: &mut Process, args: &[&str]) -> xdb::Result<()> {
    let mut address = None;
    let mut count = DEFAULT_INSTRUCTION_COUNT;

    // Parse command line arguments for -c and -a flags
    let mut i = 1;
    while i < args.len() {
        match args[i] {
            "-c" if i + 1 < args.len() => {
                let Some(n) = parse::to_integral::<usize>(args[i + 1], 10) else {
                    eprintln!("Invalid instruction count.");
                    return Ok(());
                };
                count = n;
                i += 2; // Skip the argument we just consumed
            }
            "-a" if i + 1 < args.len() => {
                let Some(addr) = parse::to_integral::<u64>(args[i + 1], 16) else {
                    eprintln!("Invalid address. Use 0x prefix for hex addresses.");
                    return Ok(());
                };
                address = Some(VirtAddr(addr));
                i += 2; // Skip the argument we just consumed
            }
            other => {
                eprintln!("Unknown argument: {other}");
                return Ok(());
            }
        }
    }

    print_disassembly(process, address, count)
}

pub fn print_disassembly(
    process: &Process,
    address: Option<VirtAddr>,
    count: usize,
) -> xdb::Result<()> {
    let instructions = Disassembler::new(process).disassemble(count, address)?;
    for instruction in instructions {
        println!("{:#018x}: {}", instruction.address.addr(), instruction.text);
    }
    Ok(())
}
